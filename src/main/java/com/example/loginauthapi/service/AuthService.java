package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.repositories.UserRepository;
import com.example.loginauthapi.infra.security.TokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, TokenService tokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
    }

    /**
     * Autentica um usuário e retorna os dados necessários para criar o cookie
     */
    public Map<String, Object> authenticateUser(LoginRequestDTO loginRequest) {
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
                throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Credenciais inválidas");
            }

            String token = tokenService.generateToken(user);
            logger.info("User authenticated successfully: {}", user.getEmail());

            Map<String, Object> result = new HashMap<>();
            result.put("user", Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "name", user.getName(),
                "role", user.getRole().name()
            ));
            result.put("token", token);
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
                .secure(false) // Simplificado para desenvolvimento
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
    public void registerUser(RegisterRequestDTO registerRequest) {
        // Verifica se o email já está cadastrado
        if (userRepository.findByEmail(registerRequest.email()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email já cadastrado");
        }
        
        // Cria o usuário
        User user = new User();
        user.setName(registerRequest.name());
        user.setEmail(registerRequest.email());
        user.setPassword(passwordEncoder.encode(registerRequest.password()));
        user.setRole(com.example.loginauthapi.domain.UserRole.USER);
        
        userRepository.save(user);
    }

    /**
     * Verifica se um token é válido e retorna os dados do usuário
     */
    public Map<String, Object> validateTokenAndGetUser(String token) {
        logger.debug("Validating token: {}", token != null ? "[PRESENT]" : "[NULL]");
        
        if (token == null || token.isEmpty()) {
            logger.debug("No token found in cookies");
            return Map.of(
                "authenticated", false,
                "message", "Nenhum token encontrado nos cookies"
            );
        }

        try {
            String userEmail = tokenService.validateToken(token);
            
            if (userEmail.isEmpty()) {
                logger.debug("Invalid or expired token");
                return Map.of(
                    "authenticated", false,
                    "message", "Token inválido ou expirado"
                );
            }

            User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> {
                    logger.error("User not found for email: {}", userEmail);
                    return new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Usuário não encontrado");
                });

            logger.debug("Token validated successfully for user: {}", user.getName());
            
            return Map.of(
                "authenticated", true,
                "user", userEmail,
                "role", user.getRole().name()
            );
            
        } catch (ResponseStatusException e) {
            logger.error("Authorization error: {}", e.getReason());
            return Map.of(
                "authenticated", false,
                "message", "Erro de autorização: " + e.getReason()
            );
        } catch (Exception e) {
            logger.error("Internal error during validation: {}", e.getMessage(), e);
            return Map.of(
                "authenticated", false,
                "message", "Erro interno: " + e.getMessage()
            );
        }
    }

    /**
     * Cria um cookie de logout (expira imediatamente)
     */
    public ResponseCookie createLogoutCookie() {
        return ResponseCookie.from("jwt", "")
            .httpOnly(true)
            .secure(false) // Simplificado para desenvolvimento
            .path("/")
            .maxAge(0) // Expira imediatamente
            .sameSite("Lax") // Simplificado para desenvolvimento
            .build();
    }
}
