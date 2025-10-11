package com.example.loginauthapi.controller;

import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
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

import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Autenticação", description = "Endpoints para registro e login de usuários")
public class AuthController {

	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	@Autowired
	private AuthService authService;

	@ApiResponses(value = { 
		    @ApiResponse(responseCode = "200", description = "Login realizado com sucesso"),
		    @ApiResponse(responseCode = "401", description = "Credenciais inválidas"),
		    @ApiResponse(responseCode = "400", description = "Requisição inválida")
		})
	@PostMapping("/login")
	public ResponseEntity<Map<String, Object>> login(
		@RequestBody @Valid LoginRequestDTO body,
		HttpServletRequest request,
		HttpServletResponse response
	) {
	    logger.info("Login attempt for email: {}", body.email());
	    
	    try {
	        Map<String, Object> authData = authService.authenticateUser(body);
	        String token = (String) authData.get("token");
	        
	        var responseCookie = authService.createAuthCookie(token, request);
	        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
	        
	        authData.remove("token");
	        
	        logger.info("Login successful for user: {}", body.email());
	        return ResponseEntity.ok().body(authData);
	        
	    } catch (Exception e) {
	        logger.error("Login failed for email: {} - {}", body.email(), e.getMessage());
	        throw e;
	    }
	}

	@Operation(summary = "Registro de usuário", description = "Cria uma nova conta de usuário")
	@ApiResponses({ @ApiResponse(responseCode = "200", description = "Registro bem-sucedido"),
			@ApiResponse(responseCode = "400", description = "Dados inválidos") })
	@PostMapping("/register")
	public ResponseEntity<Void> register(@RequestBody @Valid RegisterRequestDTO body) {
	    try {
	        authService.registerUser(body);
	        return ResponseEntity.ok().build();
	    } catch (Exception e) {
	        logger.error("Erro durante registro: {}", e.getMessage(), e);
	        throw e;
	    }
	}
	
	@PostMapping("/logout")
	@Operation(summary = "Logout", description = "Invalida o token JWT e limpa o cookie")
	public ResponseEntity<Void> logout(HttpServletResponse response) {
	    var cookie = authService.createLogoutCookie();
	    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
	    return ResponseEntity.ok().build();
	}

	@GetMapping("/check")
	@Operation(summary = "Verificar autenticação", description = "Verifica se o usuário está autenticado via cookie HTTP-only")
	@ApiResponses({
	    @ApiResponse(responseCode = "200", description = "Usuário autenticado"),
	    @ApiResponse(responseCode = "401", description = "Não autenticado")
	})
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
	
	
}