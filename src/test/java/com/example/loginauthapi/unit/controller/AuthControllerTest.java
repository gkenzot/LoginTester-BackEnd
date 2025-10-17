package com.example.loginauthapi.unit.controller;

import com.example.loginauthapi.config.TestSecurityConfig;
import com.example.loginauthapi.controller.AuthController;
import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.domain.UserRole;
import java.util.UUID;
import com.example.loginauthapi.service.AuthService;
import com.example.loginauthapi.service.TokenBlacklistService;
import com.example.loginauthapi.infra.security.TokenService;
import com.example.loginauthapi.infra.security.CustomUserDetailsService;
import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import org.springframework.http.ResponseCookie;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthController.class)
@Import(TestSecurityConfig.class)
@WithMockUser
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private TokenBlacklistService tokenBlacklistService;

    @MockBean
    private TokenService tokenService;

    @MockBean
    private CustomUserDetailsService userDetailsService;


    @Autowired
    private ObjectMapper objectMapper;

    private LoginRequestDTO loginRequest;
    private RegisterRequestDTO registerRequest;

    @BeforeEach
    void setUp() {
        loginRequest = new LoginRequestDTO("test@mail.com", "password123");
        registerRequest = new RegisterRequestDTO(
            "Test User",
            "test@mail.com",
            "Password123!",
            "Password123!"
        );
        
        // Mock dos métodos de cookie que são chamados pelo controller
        when(authService.createAuthCookie(anyString(), any(HttpServletRequest.class)))
            .thenReturn(org.springframework.http.ResponseCookie.from("jwt", "mock-token").build());
        when(authService.createLogoutCookie())
            .thenReturn(org.springframework.http.ResponseCookie.from("jwt", "").maxAge(0).build());
        when(authService.logoutWithBlacklist(anyString(), anyString(), anyString()))
            .thenReturn(org.springframework.http.ResponseCookie.from("jwt", "").maxAge(0).build());
        when(authService.logoutWithBlacklist(isNull(), anyString(), isNull()))
            .thenReturn(org.springframework.http.ResponseCookie.from("jwt", "").maxAge(0).build());
    }

    // Testes de Login (5 testes)

    @Test
    void login_WithValidCredentials_ShouldReturnSuccess() throws Exception {
        // Given
        Map<String, Object> authData = new HashMap<>();
        authData.put("user", Map.of("id", "user-123", "email", "test@mail.com", "name", "Test User", "role", "USER"));
        authData.put("message", "Login realizado com sucesso");
        authData.put("accessToken", "mock-access-token");
        authData.put("refreshToken", "mock-refresh-token");
        when(authService.authenticateUser(any(LoginRequestDTO.class))).thenReturn(authData);

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Login realizado com sucesso"))
                .andExpect(jsonPath("$.user.email").value("test@mail.com"))
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }

    @Test
    void login_WithInvalidCredentials_ShouldReturnUnauthorized() throws Exception {
        // Given
        when(authService.authenticateUser(any(LoginRequestDTO.class)))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.UNAUTHORIZED, "Credenciais inválidas"));

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_WithInvalidJson_ShouldReturnBadRequest() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("invalid json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_WithMissingEmail_ShouldReturnBadRequest() throws Exception {
        // Given
        LoginRequestDTO invalidRequest = new LoginRequestDTO("", "password123");
        when(authService.authenticateUser(any(LoginRequestDTO.class)))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "Email é obrigatório"));

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_WithMissingPassword_ShouldReturnBadRequest() throws Exception {
        // Given
        LoginRequestDTO invalidRequest = new LoginRequestDTO("test@mail.com", "");
        when(authService.authenticateUser(any(LoginRequestDTO.class)))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "Senha é obrigatória"));

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    // Testes de Registro (5 testes)

    @Test
    void register_WithValidData_ShouldReturnSuccess() throws Exception {
        // Given
        User mockUser = new User();
        mockUser.setId(UUID.randomUUID());
        mockUser.setName("Test User");
        mockUser.setEmail("test@mail.com");
        mockUser.setRole(UserRole.UNVERIFIED);
        
        when(authService.registerUser(any(RegisterRequestDTO.class))).thenReturn(mockUser);
        
        // Mock do TokenService para gerar tokens
        Map<String, String> mockTokenPair = new HashMap<>();
        mockTokenPair.put("accessToken", "mock-access-token");
        mockTokenPair.put("refreshToken", "mock-refresh-token");
        when(tokenService.generateTokenPair(any(User.class))).thenReturn(mockTokenPair);
        
        // Mock do createAuthCookie para evitar NullPointerException
        ResponseCookie mockCookie = ResponseCookie.from("jwt", "mock-token")
            .httpOnly(true)
            .secure(false)
            .path("/")
            .maxAge(Duration.ofMinutes(15))
            .build();
        when(authService.createAuthCookie(anyString(), any(HttpServletRequest.class)))
            .thenReturn(mockCookie);

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());
    }

    @Test
    void register_WithExistingEmail_ShouldReturnBadRequest() throws Exception {
        // Given
        doThrow(new org.springframework.web.server.ResponseStatusException(
            org.springframework.http.HttpStatus.BAD_REQUEST, "Email já cadastrado"))
            .when(authService).registerUser(any(RegisterRequestDTO.class));

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_WithPasswordMismatch_ShouldReturnBadRequest() throws Exception {
        // Given
        RegisterRequestDTO invalidRequest = new RegisterRequestDTO(
            "Test User",
            "test@mail.com",
            "Password123!",
            "DifferentPassword123!"
        );
        doThrow(new org.springframework.web.server.ResponseStatusException(
            org.springframework.http.HttpStatus.BAD_REQUEST, "Senha e confirmação de senha não coincidem"))
            .when(authService).registerUser(any(RegisterRequestDTO.class));

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_WithWeakPassword_ShouldReturnBadRequest() throws Exception {
        // Given
        RegisterRequestDTO weakPasswordRequest = new RegisterRequestDTO(
            "Test User",
            "test@mail.com",
            "123",
            "123"
        );
        doThrow(new org.springframework.web.server.ResponseStatusException(
            org.springframework.http.HttpStatus.BAD_REQUEST, "Senha não atende aos critérios de segurança"))
            .when(authService).registerUser(any(RegisterRequestDTO.class));

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(weakPasswordRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_WithInvalidJson_ShouldReturnBadRequest() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("invalid json"))
                .andExpect(status().isBadRequest());
    }

    // Testes de Logout (3 testes)

    @Test
    void logout_WithValidToken_ShouldReturnSuccess() throws Exception {
        // Given
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "test@mail.com",
            "role", "USER"
        );
        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(post("/api/auth/logout")
                .cookie(new jakarta.servlet.http.Cookie("jwt", "valid-token"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\": \"refresh-token\"}"))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }

    @Test
    void logout_WithInvalidToken_ShouldStillReturnSuccess() throws Exception {
        // Given
        Map<String, Object> authResult = Map.of(
            "authenticated", false,
            "message", "Token inválido"
        );
        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(post("/api/auth/logout")
                .cookie(new jakarta.servlet.http.Cookie("jwt", "invalid-token"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\": \"refresh-token\"}"))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }

    @Test
    void logout_WithoutToken_ShouldReturnSuccess() throws Exception {
        // Given
        when(authService.logoutWithBlacklist(isNull(), anyString(), isNull()))
            .thenReturn(org.springframework.http.ResponseCookie.from("jwt", "").build());

        // When & Then
        mockMvc.perform(post("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\": \"refresh-token\"}"))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }

    // Testes de Refresh Token (3 testes)

    @Test
    void refreshToken_WithValidRefreshToken_ShouldReturnSuccess() throws Exception {
        // Given
        Map<String, Object> authData = new HashMap<>();
        authData.put("user", Map.of("id", "user-123", "email", "test@mail.com", "name", "Test User", "role", "USER"));
        authData.put("refreshToken", "new-refresh-token");
        authData.put("message", "Token renovado com sucesso");
        authData.put("accessToken", "new-access-token");
        when(authService.refreshAccessToken(anyString())).thenReturn(authData);

        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\": \"valid-refresh-token\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Token renovado com sucesso"))
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }

    @Test
    void refreshToken_WithInvalidRefreshToken_ShouldReturnUnauthorized() throws Exception {
        // Given
        when(authService.refreshAccessToken(anyString()))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.UNAUTHORIZED, "Refresh token inválido"));

        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\": \"invalid-refresh-token\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshToken_WithMissingRefreshToken_ShouldReturnBadRequest() throws Exception {
        // Given
        when(authService.refreshAccessToken(isNull()))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "Refresh token é obrigatório"));

        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // Testes de Check Auth (2 testes)

    @Test
    void checkAuth_WithValidToken_ShouldReturnAuthenticated() throws Exception {
        // Given
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "test@mail.com",
            "role", "USER"
        );
        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(get("/api/auth/check")
                .cookie(new jakarta.servlet.http.Cookie("jwt", "valid-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.user").value("test@mail.com"));
    }

    @Test
    void checkAuth_WithInvalidToken_ShouldReturnUnauthorized() throws Exception {
        // Given
        Map<String, Object> authResult = Map.of(
            "authenticated", false,
            "message", "Token inválido ou expirado"
        );
        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(get("/api/auth/check")
                .cookie(new jakarta.servlet.http.Cookie("jwt", "invalid-token")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.authenticated").value(false))
                .andExpect(jsonPath("$.message").value("Token inválido ou expirado"));
    }

    // Testes de Blacklist Stats (2 testes)

    @Test
    void getBlacklistStats_WithAdminUser_ShouldReturnStats() throws Exception {
        // Given
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "admin@mail.com",
            "role", "ADMIN"
        );
        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);
        
        TokenBlacklistService.BlacklistStats stats = mock(TokenBlacklistService.BlacklistStats.class);
        when(stats.getTokensBlacklisted()).thenReturn(10L);
        when(stats.getTokensRemoved()).thenReturn(5L);
        when(stats.getActiveBlacklistedTokens()).thenReturn(3L);
        when(tokenBlacklistService.getBlacklistStats()).thenReturn(stats);

        // When & Then
        mockMvc.perform(get("/api/auth/blacklist/stats")
                .cookie(new jakarta.servlet.http.Cookie("jwt", "admin-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokensBlacklisted").value(10))
                .andExpect(jsonPath("$.tokensRemoved").value(5))
                .andExpect(jsonPath("$.activeBlacklistedTokens").value(3));
    }

    @Test
    void getBlacklistStats_WithNonAdminUser_ShouldReturnForbidden() throws Exception {
        // Given
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "user@mail.com",
            "role", "USER"
        );
        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(get("/api/auth/blacklist/stats")
                .cookie(new jakarta.servlet.http.Cookie("jwt", "user-token")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Acesso negado"))
                .andExpect(jsonPath("$.message").value("Apenas administradores podem acessar estatísticas da blacklist"));
    }
}
