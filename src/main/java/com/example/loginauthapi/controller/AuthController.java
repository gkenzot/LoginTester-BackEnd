package com.example.loginauthapi.controller;

import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.service.AuthService;
import com.example.loginauthapi.service.TokenBlacklistService;
import com.example.loginauthapi.service.EmailVerificationService;
import com.example.loginauthapi.service.EmailVerificationCodeService;
import com.example.loginauthapi.infra.security.TokenService;
import com.example.loginauthapi.config.RateLimit;
import com.example.loginauthapi.annotation.Auditable;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Autenticação", description = "Endpoints para registro e login de usuários")
@RequiredArgsConstructor
public class AuthController {

	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final TokenBlacklistService tokenBlacklistService;
    private final EmailVerificationService emailVerificationService;
    private final EmailVerificationCodeService emailVerificationCodeService;
    private final TokenService tokenService;

	@ApiResponses(value = { 
		    @ApiResponse(responseCode = "200", description = "Login realizado com sucesso"),
		    @ApiResponse(responseCode = "401", description = "Credenciais inválidas"),
		    @ApiResponse(responseCode = "400", description = "Requisição inválida"),
		    @ApiResponse(responseCode = "429", description = "Rate limit excedido")
		})
	@PostMapping("/login")
	// @RateLimit(RateLimit.EndpointType.LOGIN)
	@Auditable(eventType = "LOGIN_ATTEMPT", description = "Tentativa de login do usuário")
	public ResponseEntity<Map<String, Object>> login(
		@RequestBody @Valid LoginRequestDTO body,
		HttpServletRequest request,
		HttpServletResponse response
	) {
	    logger.info("Login attempt for email: {}", body.email());
	    
	    try {
	        Map<String, Object> authData = authService.authenticateUser(body);
	        String accessToken = (String) authData.get("accessToken");
	        
	        var responseCookie = authService.createAuthCookie(accessToken, request);
	        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
	        
	        authData.remove("accessToken");
	        authData.remove("refreshToken");
	        
	        logger.info("Login successful for user: {}", body.email());
	        return ResponseEntity.ok().body(authData);
	        
	    } catch (Exception e) {
	        logger.error("Login failed for email: {} - {}", body.email(), e.getMessage());
	        throw e;
	    }
	}

	@Operation(summary = "Registro de usuário", description = "Cria uma nova conta de usuário")
	@ApiResponses({ @ApiResponse(responseCode = "200", description = "Registro bem-sucedido"),
			@ApiResponse(responseCode = "400", description = "Dados inválidos"),
			@ApiResponse(responseCode = "429", description = "Rate limit excedido") })
	@PostMapping("/register")
	@RateLimit(RateLimit.EndpointType.REGISTER)
	@Auditable(eventType = "USER_REGISTRATION", description = "Registro de novo usuário")
	public ResponseEntity<Map<String, Object>> register(
		@RequestBody @Valid RegisterRequestDTO body,
		HttpServletRequest request,
		HttpServletResponse response
	) {
	    try {
	        var user = authService.registerUser(body);
	        
	        // NÃO enviar código de verificação automaticamente no registro
	        // O código será enviado apenas quando o usuário clicar em "VERIFICAR EMAIL"
	        logger.info("User registered successfully: {}", user.getEmail());
	        
	        // Gerar tokens de autenticação para o usuário registrado
	        Map<String, String> tokenPair = tokenService.generateTokenPair(user);
	        String accessToken = tokenPair.get("accessToken");
	        
	        // Criar cookie de autenticação
	        var responseCookie = authService.createAuthCookie(accessToken, request);
	        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
	        
	        // Preparar resposta com dados do usuário
	        Map<String, Object> authData = new HashMap<>();
	        Map<String, Object> userInfo = new HashMap<>();
	        userInfo.put("id", user.getId());
	        userInfo.put("email", user.getEmail());
	        userInfo.put("name", user.getName());
	        userInfo.put("role", user.getRole().name());
	        authData.put("user", userInfo);
	        authData.put("message", "Usuário registrado com sucesso. Clique em 'VERIFICAR EMAIL' para ativar sua conta.");
	        
	        // Remover tokens da resposta (já enviados via cookie)
	        authData.remove("accessToken");
	        authData.remove("refreshToken");
	        
	        logger.info("User registered and authenticated successfully: {}", user.getEmail());
	        return ResponseEntity.ok(authData);
	    } catch (Exception e) {
	        logger.error("Erro durante registro: {}", e.getMessage(), e);
	        throw e;
	    }
	}
	
	@PostMapping("/logout")
	@Operation(summary = "Logout", description = "Invalida o token JWT, adiciona à blacklist e limpa o cookie")
	@Auditable(eventType = "LOGOUT", description = "Logout do usuário")
	public ResponseEntity<Void> logout(
	    @CookieValue(name = "jwt", required = false) String accessToken,
	    @RequestBody(required = false) Map<String, String> request,
	    HttpServletResponse response) {
	    
	    logger.info("Logout request");
	    
	    try {
	        String refreshToken = null;
	        String userEmail = null;
	        
	        // Obter refresh token do body se fornecido
	        if (request != null) {
	            refreshToken = request.get("refreshToken");
	        }
	        
	        // Se temos access token, validar para obter email do usuário
	        if (accessToken != null && !accessToken.isEmpty()) {
	            Map<String, Object> authResult = authService.validateTokenAndGetUser(accessToken);
	            if ((Boolean) authResult.get("authenticated")) {
	                userEmail = (String) authResult.get("user");
	            }
	        }
	        
	        // ✅ Logout com blacklist
	        var cookie = authService.logoutWithBlacklist(accessToken, refreshToken, userEmail);
	        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
	        
	        logger.info("Logout completed successfully");
	        return ResponseEntity.ok().build();
	        
	    } catch (Exception e) {
	        logger.error("Logout failed: {}", e.getMessage());
	        // Mesmo com erro, limpar cookie
	        var cookie = authService.createLogoutCookie();
	        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
	        return ResponseEntity.ok().build();
	    }
	}

	@PostMapping("/refresh")
	@Operation(summary = "Renovar token", description = "Renova o access token usando um refresh token válido")
	@ApiResponses({
	    @ApiResponse(responseCode = "200", description = "Token renovado com sucesso"),
	    @ApiResponse(responseCode = "401", description = "Refresh token inválido"),
	    @ApiResponse(responseCode = "429", description = "Rate limit excedido")
	})
	@RateLimit(RateLimit.EndpointType.CHECK)
	@Auditable(eventType = "TOKEN_REFRESH", description = "Renovação de token de acesso")
	public ResponseEntity<Map<String, Object>> refreshToken(
	    @RequestBody Map<String, String> request,
	    HttpServletRequest httpRequest,
	    HttpServletResponse response) {
	    
	    String refreshToken = request.get("refreshToken");
	    logger.info("Refresh token request");
	    
	    try {
	        Map<String, Object> authData = authService.refreshAccessToken(refreshToken);
	        String accessToken = (String) authData.get("accessToken");
	        
	        var responseCookie = authService.createAuthCookie(accessToken, httpRequest);
	        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
	        
	        authData.remove("accessToken");
	        
	        logger.info("Token refreshed successfully");
	        return ResponseEntity.ok().body(authData);
	        
	    } catch (Exception e) {
	        logger.error("Token refresh failed: {}", e.getMessage());
	        throw e;
	    }
	}

	@GetMapping("/check")
	@Operation(summary = "Verificar autenticação", description = "Verifica se o usuário está autenticado via cookie HTTP-only")
	@ApiResponses({
	    @ApiResponse(responseCode = "200", description = "Usuário autenticado"),
	    @ApiResponse(responseCode = "401", description = "Não autenticado"),
	    @ApiResponse(responseCode = "429", description = "Rate limit excedido")
	})
	@RateLimit(RateLimit.EndpointType.CHECK)
	public ResponseEntity<Map<String, Object>> checkAuth(
	    @CookieValue(name = "jwt", required = false) String token) {
	    
	    logger.debug("Auth check for token: {}", token != null ? "[PRESENT]" : "[NULL]");
	    
	    Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
	    boolean authenticated = (Boolean) authResult.get("authenticated");
	    
	    if (authenticated) {
	        return ResponseEntity.ok().body(authResult);
	    } else {
	        logger.warn("Auth check failed: {}", authResult.get("message"));
	        return ResponseEntity.status(401).body(authResult);
	    }
	}
	
	@GetMapping("/blacklist/stats")
	@Operation(summary = "Estatísticas da Blacklist", description = "Retorna estatísticas da blacklist de tokens (apenas para ADMIN)")
	@ApiResponses({
	    @ApiResponse(responseCode = "200", description = "Estatísticas retornadas com sucesso"),
	    @ApiResponse(responseCode = "401", description = "Não autenticado"),
	    @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
	    @ApiResponse(responseCode = "429", description = "Rate limit excedido")
	})
	@RateLimit(RateLimit.EndpointType.CHECK)
	public ResponseEntity<Map<String, Object>> getBlacklistStats(
	    @CookieValue(name = "jwt", required = false) String token) {
	    
	    logger.info("Blacklist stats request");
	    
	    try {
	        // Verificar autenticação
	        Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
	        boolean authenticated = (Boolean) authResult.get("authenticated");
	        
        if (!authenticated) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Não autenticado");
            errorResponse.put("message", "Token inválido ou expirado");
            
            return ResponseEntity.status(401).body(errorResponse);
        }
	        
        // Verificar se é ADMIN
        String role = (String) authResult.get("role");
        if (!"ADMIN".equals(role)) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Acesso negado");
            errorResponse.put("message", "Apenas administradores podem acessar estatísticas da blacklist");
            
            return ResponseEntity.status(403).body(errorResponse);
        }
	        
        // Obter estatísticas
        TokenBlacklistService.BlacklistStats stats = tokenBlacklistService.getBlacklistStats();
        
        Map<String, Object> response = new HashMap<>();
        response.put("tokensBlacklisted", stats.getTokensBlacklisted());
        response.put("tokensRemoved", stats.getTokensRemoved());
        response.put("activeBlacklistedTokens", stats.getActiveBlacklistedTokens());
        response.put("timestamp", System.currentTimeMillis());
	        
	        logger.info("Blacklist stats retrieved successfully");
	        return ResponseEntity.ok().body(response);
	        
    } catch (Exception e) {
        logger.error("Error retrieving blacklist stats: {}", e.getMessage(), e);
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Erro interno");
        errorResponse.put("message", "Falha ao obter estatísticas da blacklist");
        
        return ResponseEntity.status(500).body(errorResponse);
    }
	}
	
	
}