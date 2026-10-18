package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.LoginRequestDTO;
import org.springframework.beans.factory.annotation.Value;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.repositories.UserRepository;
import com.example.loginauthapi.infra.security.TokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    
    private final UserRepository userRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordValidator passwordValidator;
    private final TokenService tokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final AuditService auditService;
    private final AlertRulesEngine alertRulesEngine;

    public AuthService(UserRepository userRepository, UserService userService, PasswordEncoder passwordEncoder,
                      PasswordValidator passwordValidator, TokenService tokenService,
                      TokenBlacklistService tokenBlacklistService, AuditService auditService, AlertRulesEngine alertRulesEngine) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.passwordValidator = passwordValidator;
        this.tokenService = tokenService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.auditService = auditService;
        this.alertRulesEngine = alertRulesEngine;
    }

    /**
     * Autentica um usuário com auditoria e detecção de padrões
     */
    @Transactional(readOnly = true)
    public Map<String, Object> authenticateUser(LoginRequestDTO loginRequest) {
        return authenticateUserWithAudit(loginRequest, null, null);
    }

    /**
     * Autentica um usuário e retorna os dados necessários para criar o cookie
     */
    @Transactional(readOnly = true)
    public Map<String, Object> authenticateUserWithAudit(LoginRequestDTO loginRequest, String ipAddress, String userAgent) {
        logger.info("Authenticating user: {}", loginRequest.email());
        
        try {
            User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> {
                    logger.warn("User not found: {}", loginRequest.email());
                    return new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Credenciais inválidas");
                });

            boolean passwordMatches = passwordEncoder.matches(loginRequest.password(), user.getPassword());
            if (!passwordMatches) {
                logger.warn("Invalid password for user: {}", user.getEmail());
                
                // Log de auditoria para falha de login
                auditService.logLoginAttempt(loginRequest.email(), ipAddress, userAgent, false);
                
                // Detectar padrões suspeitos
                alertRulesEngine.evaluateLoginAttempts(ipAddress, loginRequest.email(), false, userAgent);
                
                throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Credenciais inválidas");
            }

            Map<String, String> tokenPair = tokenService.generateTokenPair(user);
            logger.info("User authenticated successfully: {}", user.getEmail());
            
            // Log de auditoria para sucesso de login
            auditService.logLoginAttempt(loginRequest.email(), ipAddress, userAgent, true);
            
            // Detectar padrões suspeitos
            alertRulesEngine.evaluateLoginAttempts(ipAddress, loginRequest.email(), true, userAgent);

            Map<String, Object> result = new HashMap<>();
            result.put("user", userService.toUserResponseDTO(user));
            result.put("accessToken", tokenPair.get("accessToken"));
            result.put("refreshToken", tokenPair.get("refreshToken"));
            result.put("message", "Login realizado com sucesso");
            return result;
            
        } catch (ResponseStatusException e) {
            logger.error("Authentication error: {}", e.getReason());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during authentication: {}", e.getMessage(), e);
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno do servidor");
        }
    }

    /**
     * Cria um cookie de autenticação baseado no protocolo da requisição
     */
    public ResponseCookie createAuthCookie(String token, HttpServletRequest request) {
        logger.debug("Creating auth cookie for token: {}", token != null ? "[PRESENT]" : "[NULL]");
        
        try {
            boolean isSecure = request.isSecure() || 
                              request.getHeader("X-Forwarded-Proto") != null && 
                              request.getHeader("X-Forwarded-Proto").equals("https");
            
            ResponseCookie cookie = ResponseCookie.from("jwt", token != null ? token : "")
                .httpOnly(true)
                .secure(isSecure)
                .path("/")
                .maxAge(Duration.ofHours(1))
                .sameSite("Lax") // Simplificado para desenvolvimento
                .build();
            
            logger.debug("Auth cookie created successfully");
            return cookie;
        } catch (Exception e) {
            logger.error("Error creating auth cookie: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Registra um novo usuário
     */
    @Transactional
    public User registerUser(RegisterRequestDTO registerRequest) {
        return registerUserWithAudit(registerRequest, null, null);
    }

    /**
     * Registra um novo usuário com auditoria
     */
    @Transactional
    public User registerUserWithAudit(RegisterRequestDTO registerRequest, String ipAddress, String userAgent) {
        logger.info("Registering new user: {}", registerRequest.email());
        
        try {
            // Validação de confirmação de senha
            if (!registerRequest.password().equals(registerRequest.confirmPassword())) {
                logger.warn("Password confirmation mismatch for user: {}", registerRequest.email());
                auditService.logUserRegistration(registerRequest.email(), ipAddress, userAgent, false);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Senha e confirmação de senha não coincidem");
            }
            
            // Validação adicional de força da senha
            passwordValidator.validate(registerRequest.password());
            
            // Verifica se o email já está cadastrado
            if (userRepository.findByEmail(registerRequest.email()).isPresent()) {
                logger.warn("Email already exists: {}", registerRequest.email());
                auditService.logUserRegistration(registerRequest.email(), ipAddress, userAgent, false);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email já cadastrado");
            }
            
            // Cria o usuário
            User user = new User();
            user.setName(registerRequest.name());
            user.setEmail(registerRequest.email());
            user.setPassword(passwordEncoder.encode(registerRequest.password()));
            user.setRole(com.example.loginauthapi.domain.UserRole.UNVERIFIED);
            
            User savedUser = userRepository.save(user);
            logger.info("User registered successfully: {}", registerRequest.email());
            
            // Log de auditoria para sucesso de registro
            auditService.logUserRegistration(registerRequest.email(), ipAddress, userAgent, true);
            
            return savedUser;
            
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during registration: {}", e.getMessage(), e);
            auditService.logUserRegistration(registerRequest.email(), ipAddress, userAgent, false);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno do servidor");
        }
    }
    
    /**
     * Verifica se um token é válido e retorna os dados do usuário
     */
    @Transactional(readOnly = true)
    public Map<String, Object> validateTokenAndGetUser(String token) {
        logger.debug("Validating token: {}", token != null ? "[PRESENT]" : "[NULL]");
        
        if (token == null || token.isEmpty()) {
            logger.debug("No token found in cookies");
            Map<String, Object> result = new HashMap<>();
            result.put("authenticated", false);
            result.put("message", "Nenhum token encontrado nos cookies");
            return result;
        }

        try {
            String userEmail = tokenService.validateToken(token);
            
            if (userEmail.isEmpty()) {
                logger.debug("Invalid or expired token");
                Map<String, Object> result = new HashMap<>();
                result.put("authenticated", false);
                result.put("message", "Token inválido ou expirado");
                return result;
            }

            User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> {
                    logger.error("User not found for email: {}", userEmail);
                    return new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Usuário não encontrado");
                });

            logger.debug("Token validated successfully for user: {}", user.getName());
            
            Map<String, Object> result = new HashMap<>();
            result.put("authenticated", true);
            result.put("user", userEmail);
            result.put("role", user.getRole().name());
            result.put("accessFlags", accessFlagsToList(user.getAccessFlags()));
            result.put("preferredLanguage", user.getPreferredLanguage() != null && !user.getPreferredLanguage().isBlank() ? user.getPreferredLanguage() : "pt-BR");
            return result;
            
        } catch (ResponseStatusException e) {
            logger.error("Authorization error: {}", e.getReason());
            Map<String, Object> result = new HashMap<>();
            result.put("authenticated", false);
            result.put("message", "Erro de autorização: " + e.getReason());
            return result;
        } catch (Exception e) {
            logger.error("Internal error during validation: {}", e.getMessage(), e);
            Map<String, Object> result = new HashMap<>();
            result.put("authenticated", false);
            result.put("message", "Erro interno: " + e.getMessage());
            return result;
        }
    }

    /**
     * Valida acesso por flag: ADMIN sempre permite; USER só se tiver a flag; UNVERIFIED nega.
     * @param token JWT (cookie ou header)
     * @param requiredFlag código da flag exigida (ex: "USER_MANAGE")
     * @throws ResponseStatusException 401 se não autenticado, 403 se sem permissão
     */
    @Transactional(readOnly = true)
    public void validateAccessByFlag(String token, String requiredFlag) {
        Map<String, Object> authResult = validateTokenAndGetUser(token);
        Boolean authenticated = (Boolean) authResult.get("authenticated");
        if (!Boolean.TRUE.equals(authenticated)) {
            logger.warn("Access by flag denied: not authenticated");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                authResult.get("message") != null ? authResult.get("message").toString() : "Token inválido ou expirado");
        }
        String role = (String) authResult.get("role");
        if ("ADMIN".equals(role)) {
            logger.debug("Access by flag allowed: ADMIN");
            return;
        }
        if ("USER".equals(role)) {
            @SuppressWarnings("unchecked")
            List<String> accessFlags = (List<String>) authResult.get("accessFlags");
            if (accessFlags != null && accessFlags.contains(requiredFlag)) {
                logger.debug("Access by flag allowed: USER with flag {}", requiredFlag);
                return;
            }
            logger.warn("Access by flag denied: USER without flag {}", requiredFlag);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                "Acesso negado - permissão (flag " + requiredFlag + ") necessária");
        }
        logger.warn("Access by flag denied: role {} (UNVERIFIED or other)", role);
        throw new ResponseStatusException(HttpStatus.FORBIDDEN,
            "Acesso negado - apenas ADMIN ou USER com a permissão correspondente podem acessar");
    }

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    /**
     * Cria um cookie de logout (expira imediatamente).
     * Em produção (HTTPS), configurar app.cookie.secure=true.
     */
    public ResponseCookie createLogoutCookie() {
        return ResponseCookie.from("jwt", "")
            .httpOnly(true)
            .secure(cookieSecure)
            .path("/")
            .maxAge(0)
            .sameSite("Lax")
            .build();
    }
    
    /**
     * ✅ NOVO: Logout com blacklist de tokens
     * Invalida tokens atuais e adiciona à blacklist
     */
    @Transactional
    public ResponseCookie logoutWithBlacklist(String accessToken, String refreshToken, String userEmail) {
        logger.info("Logout with blacklist for user: {}", userEmail);
        
        try {
            // Adicionar tokens à blacklist
            if (accessToken != null && !accessToken.isEmpty()) {
                tokenBlacklistService.blacklistToken(accessToken, userEmail, "logout");
                logger.debug("Access token blacklisted");
            }
            
            if (refreshToken != null && !refreshToken.isEmpty()) {
                tokenBlacklistService.blacklistToken(refreshToken, userEmail, "logout");
                logger.debug("Refresh token blacklisted");
            }
            
            logger.info("Logout with blacklist completed for user: {}", userEmail);
            
        } catch (Exception e) {
            logger.error("Error during logout with blacklist: {}", e.getMessage(), e);
            // Não falhar o logout por erro de blacklist
        }
        
        // Retornar cookie de logout
        return createLogoutCookie();
    }
    
    /**
     * ✅ NOVO: Blacklist todos os tokens de um usuário (logout global)
     */
    @Transactional
    public void blacklistAllUserTokens(String userEmail, String reason) {
        logger.info("Blacklisting all tokens for user: {}, reason: {}", userEmail, reason);
        
        try {
            tokenBlacklistService.blacklistAllUserTokens(userEmail, reason);
            logger.info("All tokens blacklisted for user: {}", userEmail);
            
        } catch (Exception e) {
            logger.error("Error blacklisting all user tokens: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Renova o access token usando um refresh token válido
     */
    @Transactional
    public Map<String, Object> refreshAccessToken(String refreshToken) {
        logger.info("Refreshing access token");
        
        try {
            // Validar o refresh token
            String email = tokenService.validateRefreshToken(refreshToken);
            if (email == null || email.isEmpty()) {
                logger.warn("Invalid refresh token");
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token inválido");
            }
            
            // Buscar o usuário
            User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("User not found for refresh token: {}", email);
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuário não encontrado");
                });
            
            // Gerar novo par de tokens
            Map<String, String> tokenPair = tokenService.generateTokenPair(user);
            logger.info("Access token refreshed successfully for user: {}", user.getEmail());
            
            Map<String, Object> result = new HashMap<>();
            result.put("user", userService.toUserResponseDTO(user));
            result.put("accessToken", tokenPair.get("accessToken"));
            result.put("refreshToken", tokenPair.get("refreshToken"));
            result.put("message", "Token renovado com sucesso");
            return result;
            
        } catch (ResponseStatusException e) {
            logger.error("Refresh token error: {}", e.getReason());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during token refresh: {}", e.getMessage(), e);
            throw new ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno do servidor");
        }
    }

    private static List<String> accessFlagsToList(Set<String> accessFlags) {
        if (accessFlags == null) {
            return List.of();
        }
        return new ArrayList<>(accessFlags);
    }
}
