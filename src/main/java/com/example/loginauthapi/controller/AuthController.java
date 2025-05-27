// src/main/java/com/example/loginauthapi/controllers/AuthController.java
package com.example.loginauthapi.controller;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.domain.UserRole;
import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.repositories.UserRepository;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import com.example.loginauthapi.infra.security.TokenService;

import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/auth")
@Tag(name = "Autenticação", description = "Endpoints para registro e login de usuários")
public class AuthController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private TokenService tokenService;

	@ApiResponses(value = { 
		    @ApiResponse(responseCode = "200", description = "Login realizado com sucesso"),
		    @ApiResponse(responseCode = "401", description = "Credenciais inválidas"),
		    @ApiResponse(responseCode = "400", description = "Requisição inválida")
		})
		@PostMapping("/login")
		public ResponseEntity<Void> login(
		    @RequestBody @Valid LoginRequestDTO body,
		    HttpServletResponse response
		) {
		    // 1. Verificar se o usuário existe
		    User user = userRepository.findByEmail(body.email())
		        .orElseThrow(() -> new ResponseStatusException(
		            HttpStatus.UNAUTHORIZED, "Credenciais inválidas"));
		    
		    // 2. Verificar a senha
		    if (!passwordEncoder.matches(body.password(), user.getPassword())) {
		        throw new ResponseStatusException(
		            HttpStatus.UNAUTHORIZED, "Credenciais inválidas");
		    }
		    
		    // 3. Gerar token e cookie
		    String token = tokenService.generateToken(user);
		    
		    ResponseCookie cookie = ResponseCookie.from("jwt", token)
		        .httpOnly(true)
		        .secure(true)
		        .path("/")
		        .maxAge(Duration.ofHours(1))
		        .sameSite("Lax")
		        .build();
		    
		    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
		    return ResponseEntity.ok().build();
		}

	@Operation(summary = "Registro de usuário", description = "Cria uma nova conta de usuário")
	@ApiResponses({ @ApiResponse(responseCode = "200", description = "Registro bem-sucedido"),
			@ApiResponse(responseCode = "400", description = "Dados inválidos") })
	@PostMapping("/register")
	public ResponseEntity<Void> register(@RequestBody @Valid RegisterRequestDTO body) {
	    // Verifica se o email já está cadastrado
	    if (userRepository.findByEmail(body.email()).isPresent()) {
	        return ResponseEntity.badRequest().build(); // Retorna 400 se email existir
	    }
	    
	    // Se passar na validação, cria o usuário
	    User user = new User();
	    user.setName(body.name());
	    user.setEmail(body.email());
	    user.setPassword(passwordEncoder.encode(body.password()));
	    user.setRole(UserRole.USER);
	    
	    userRepository.save(user);
	    
	    return ResponseEntity.ok().build(); // Retorna 200 se sucesso
	}
	
	@PostMapping("/logout")
	@Operation(summary = "Logout", description = "Invalida o token JWT e limpa o cookie")
	public ResponseEntity<Void> logout(HttpServletResponse response) {
	    // Cria um cookie vazio com expiração imediata
	    ResponseCookie cookie = ResponseCookie.from("jwt", "")
	        .httpOnly(true)
	        .secure(true)
	        .path("/")
	        .maxAge(0) // Expira imediatamente
	        .sameSite("Strict")
	        .build();
	    
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
	    
	    if (token == null || token.isEmpty()) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	            .body(Map.of(
	                "authenticated", false,
	                "message", "Nenhum token encontrado nos cookies"
	            ));
	    }

	    String userEmail = tokenService.validateToken(token);
	    if (userEmail.isEmpty()) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	            .body(Map.of(
	                "authenticated", false,
	                "message", "Token inválido ou expirado"
	            ));
	    }

	    User user = userRepository.findByEmail(userEmail)
	        .orElseThrow(() -> new ResponseStatusException(
	            HttpStatus.UNAUTHORIZED, "Usuário não encontrado"));

	    return ResponseEntity.ok()
	        .body(Map.of(
	            "authenticated", true,
	            "user", userEmail,
	            "role", user.getRole().name() // Isso vai retornar "ADMIN", "USER", etc.
	        ));
	}
	
}