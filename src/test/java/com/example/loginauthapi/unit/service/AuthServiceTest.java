package com.example.loginauthapi.unit.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.domain.UserRole;
import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.repositories.UserRepository;
import com.example.loginauthapi.service.AuthService;
import com.example.loginauthapi.service.AuditService;
import com.example.loginauthapi.service.AlertRulesEngine;
import com.example.loginauthapi.service.TokenBlacklistService;
import com.example.loginauthapi.infra.security.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private TokenService tokenService;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private AuditService auditService;

    @Mock
    private AlertRulesEngine alertRulesEngine;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private LoginRequestDTO loginRequest;
    private RegisterRequestDTO registerRequest;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setEmail("test@mail.com");
        testUser.setName("Test User");
        testUser.setPassword("encodedPassword");
        testUser.setRole(UserRole.USER);

        loginRequest = new LoginRequestDTO("test@mail.com", "password123");

        registerRequest = new RegisterRequestDTO(
            "New User",
            "new@mail.com",
            "NewPass123!",
            "NewPass123!"
        );
    }

    // Testes de Autenticação (5 testes)

    @Test
    void authenticateUser_WithValidCredentials_ShouldReturnSuccess() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password123", "encodedPassword")).thenReturn(true);
        when(tokenService.generateTokenPair(testUser)).thenReturn(Map.of(
            "accessToken", "access-token",
            "refreshToken", "refresh-token"
        ));

        // When
        Map<String, Object> result = authService.authenticateUser(loginRequest);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.get("message")).isEqualTo("Login realizado com sucesso");
        assertThat(result.get("accessToken")).isEqualTo("access-token");
        assertThat(result.get("refreshToken")).isEqualTo("refresh-token");
        
        verify(auditService).logLoginAttempt(eq("test@mail.com"), isNull(), isNull(), eq(true));
        verify(alertRulesEngine).evaluateLoginAttempts(isNull(), eq("test@mail.com"), eq(true), isNull());
    }

    @Test
    void authenticateUser_WithInvalidEmail_ShouldThrowUnauthorized() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authService.authenticateUser(loginRequest))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.UNAUTHORIZED)
            .hasMessageContaining("Credenciais inválidas");
    }

    @Test
    void authenticateUser_WithInvalidPassword_ShouldThrowUnauthorized() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password123", "encodedPassword")).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> authService.authenticateUser(loginRequest))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.UNAUTHORIZED)
            .hasMessageContaining("Credenciais inválidas");
        
        verify(auditService).logLoginAttempt(eq("test@mail.com"), isNull(), isNull(), eq(false));
        verify(alertRulesEngine).evaluateLoginAttempts(isNull(), eq("test@mail.com"), eq(false), isNull());
    }

    @Test
    void authenticateUserWithAudit_WithValidCredentials_ShouldLogAudit() {
        // Given
        String ipAddress = "192.168.1.1";
        String userAgent = "Mozilla/5.0";
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password123", "encodedPassword")).thenReturn(true);
        when(tokenService.generateTokenPair(testUser)).thenReturn(Map.of(
            "accessToken", "access-token",
            "refreshToken", "refresh-token"
        ));

        // When
        Map<String, Object> result = authService.authenticateUserWithAudit(loginRequest, ipAddress, userAgent);

        // Then
        assertThat(result).isNotNull();
        verify(auditService).logLoginAttempt(eq("test@mail.com"), eq(ipAddress), eq(userAgent), eq(true));
        verify(alertRulesEngine).evaluateLoginAttempts(eq(ipAddress), eq("test@mail.com"), eq(true), eq(userAgent));
    }

    @Test
    void authenticateUser_WithException_ShouldThrowInternalServerError() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenThrow(new RuntimeException("Database error"));

        // When & Then
        assertThatThrownBy(() -> authService.authenticateUser(loginRequest))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.INTERNAL_SERVER_ERROR)
            .hasMessageContaining("Erro interno do servidor");
    }

    // Testes de Registro (5 testes)

    @Test
    void registerUser_WithValidData_ShouldRegisterSuccessfully() {
        // Given
        when(userRepository.findByEmail("new@mail.com")).thenReturn(Optional.empty());

        // When
        authService.registerUser(registerRequest);

        // Then
        verify(userRepository).save(any(User.class));
        verify(auditService).logUserRegistration(eq("new@mail.com"), isNull(), isNull(), eq(true));
    }

    @Test
    void registerUser_WithExistingEmail_ShouldThrowBadRequest() {
        // Given
        when(userRepository.findByEmail("new@mail.com")).thenReturn(Optional.of(testUser));

        // When & Then
        assertThatThrownBy(() -> authService.registerUser(registerRequest))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST)
            .hasMessageContaining("Email já cadastrado");
        
        verify(auditService).logUserRegistration(eq("new@mail.com"), isNull(), isNull(), eq(false));
    }

    @Test
    void registerUser_WithPasswordMismatch_ShouldThrowBadRequest() {
        // Given
        RegisterRequestDTO invalidRequest = new RegisterRequestDTO(
            "New User",
            "new@mail.com",
            "NewPass123!",
            "DifferentPass123!"
        );

        // When & Then
        assertThatThrownBy(() -> authService.registerUser(invalidRequest))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST)
            .hasMessageContaining("Senha e confirmação de senha não coincidem");
        
        verify(auditService).logUserRegistration(eq("new@mail.com"), isNull(), isNull(), eq(false));
    }

    @Test
    void registerUser_WithWeakPassword_ShouldThrowBadRequest() {
        // Given
        RegisterRequestDTO weakPasswordRequest = new RegisterRequestDTO(
            "New User",
            "new@mail.com",
            "123",
            "123"
        );

        // When & Then
        assertThatThrownBy(() -> authService.registerUser(weakPasswordRequest))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST)
            .hasMessageContaining("Senha não atende aos critérios de segurança");
    }

    @Test
    void registerUserWithAudit_WithValidData_ShouldLogAudit() {
        // Given
        String ipAddress = "192.168.1.1";
        String userAgent = "Mozilla/5.0";
        when(userRepository.findByEmail("new@mail.com")).thenReturn(Optional.empty());

        // When
        authService.registerUserWithAudit(registerRequest, ipAddress, userAgent);

        // Then
        verify(userRepository).save(any(User.class));
        verify(auditService).logUserRegistration(eq("new@mail.com"), eq(ipAddress), eq(userAgent), eq(true));
    }

    // Testes de Validação de Token (3 testes)

    @Test
    void validateTokenAndGetUser_WithValidToken_ShouldReturnUser() {
        // Given
        String token = "valid-token";
        when(tokenService.validateToken(token)).thenReturn("test@mail.com");
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));

        // When
        Map<String, Object> result = authService.validateTokenAndGetUser(token);

        // Then
        assertThat(result.get("authenticated")).isEqualTo(true);
        assertThat(result.get("user")).isEqualTo("test@mail.com");
        assertThat(result.get("role")).isEqualTo("USER");
    }

    @Test
    void validateTokenAndGetUser_WithInvalidToken_ShouldReturnNotAuthenticated() {
        // Given
        String token = "invalid-token";
        when(tokenService.validateToken(token)).thenReturn("");

        // When
        Map<String, Object> result = authService.validateTokenAndGetUser(token);

        // Then
        assertThat(result.get("authenticated")).isEqualTo(false);
        assertThat(result.get("message")).isEqualTo("Token inválido ou expirado");
    }

    @Test
    void validateTokenAndGetUser_WithNullToken_ShouldReturnNotAuthenticated() {
        // When
        Map<String, Object> result = authService.validateTokenAndGetUser(null);

        // Then
        assertThat(result.get("authenticated")).isEqualTo(false);
        assertThat(result.get("message")).isEqualTo("Nenhum token encontrado nos cookies");
    }

    // Testes de Cookie (2 testes)

    @Test
    void createAuthCookie_WithSecureRequest_ShouldCreateSecureCookie() {
        // Given
        when(request.isSecure()).thenReturn(true);

        // When
        ResponseCookie cookie = authService.createAuthCookie("test-token", request);

        // Then
        assertThat(cookie.getName()).isEqualTo("jwt");
        assertThat(cookie.getValue()).isEqualTo("test-token");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getPath()).isEqualTo("/");
    }

    @Test
    void createLogoutCookie_ShouldCreateExpiredCookie() {
        // When
        ResponseCookie cookie = authService.createLogoutCookie();

        // Then
        assertThat(cookie.getName()).isEqualTo("jwt");
        assertThat(cookie.getValue()).isEqualTo("");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(0);
    }
}
