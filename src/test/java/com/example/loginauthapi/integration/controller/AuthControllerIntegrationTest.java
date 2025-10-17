package com.example.loginauthapi.integration.controller;

import com.example.loginauthapi.dto.LoginRequestDTO;
import com.example.loginauthapi.dto.RegisterRequestDTO;
import com.example.loginauthapi.service.AuthService;
import com.example.loginauthapi.service.TokenBlacklistService;
import com.example.loginauthapi.infra.security.TokenService;
import com.example.loginauthapi.infra.security.CustomUserDetailsService;
import com.example.loginauthapi.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.HashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.context.annotation.Import;
import com.example.loginauthapi.config.TestSecurityConfig;
import org.springframework.http.ResponseCookie;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@WebMvcTest(com.example.loginauthapi.controller.AuthController.class)
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private TokenBlacklistService tokenBlacklistService;

    @MockBean
    private TokenService tokenService;

    @MockBean
    private CustomUserDetailsService customUserDetailsService;

    @MockBean
    private UserRepository userRepository;

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        
        // Mock default responses for cookie creation - garantir que nunca retorne null
        when(authService.createAuthCookie(anyString(), any())).thenReturn(
            org.springframework.http.ResponseCookie.from("jwt", "mock-token")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(3600)
                .build()
        );
        
        when(authService.createLogoutCookie()).thenReturn(
            org.springframework.http.ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .build()
        );
        
        when(authService.logoutWithBlacklist(anyString(), anyString(), anyString())).thenReturn(
            org.springframework.http.ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(0)
                .build()
        );
        
        // Mock default auth validation
        when(authService.validateTokenAndGetUser(anyString())).thenReturn(Map.of(
            "authenticated", false,
            "message", "Token inválido ou expirado"
        ));
        
        // Mock default refresh token
        when(authService.refreshAccessToken(anyString())).thenReturn(Map.of(
            "user", "test@example.com",
            "role", "USER", 
            "authenticated", true
        ));
    }

        @Test
        void login_WithValidCredentials_ShouldReturnSuccess() throws Exception {
            // Given
            LoginRequestDTO loginRequest = new LoginRequestDTO("test@example.com", "password123");
            Map<String, Object> authData = new HashMap<>();
            authData.put("user", "test@example.com");
            authData.put("role", "USER");
            authData.put("authenticated", true);
            authData.put("accessToken", "mock-access-token");

            when(authService.authenticateUser(any(LoginRequestDTO.class))).thenReturn(authData);
            // Mock já configurado no setUp() - não precisa reconfigurar

            // When & Then
            mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginRequest)))
                    .andDo(print())
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.user").value("test@example.com"))
                    .andExpect(jsonPath("$.role").value("USER"))
                    .andExpect(jsonPath("$.authenticated").value(true))
                    .andExpect(header().exists("Set-Cookie"));

            verify(authService).authenticateUser(any(LoginRequestDTO.class));
            verify(authService).createAuthCookie(anyString(), any());
        }

    @Test
    void login_WithInvalidCredentials_ShouldReturnUnauthorized() throws Exception {
        // Given
        LoginRequestDTO loginRequest = new LoginRequestDTO("invalid@example.com", "wrongpassword");

        when(authService.authenticateUser(any(LoginRequestDTO.class)))
                .thenThrow(new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.UNAUTHORIZED, "Credenciais inválidas"));

        // When & Then
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isUnauthorized());

        verify(authService).authenticateUser(any(LoginRequestDTO.class));
    }

    @Test
    void register_WithValidData_ShouldReturnSuccess() throws Exception {
        // Given
        RegisterRequestDTO registerRequest = new RegisterRequestDTO(
            "Test User", "test@example.com", "Password123!", "Password123!"
        );

        doNothing().when(authService).registerUser(any(RegisterRequestDTO.class));

        // When & Then
        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isOk());

        verify(authService).registerUser(any(RegisterRequestDTO.class));
    }

    @Test
    void register_WithInvalidData_ShouldReturnBadRequest() throws Exception {
        // Given
        RegisterRequestDTO registerRequest = new RegisterRequestDTO(
            "", "invalid-email", "weak", "weak"
        );

        // Mock the service to throw validation exception
        doThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "Dados inválidos"))
                .when(authService).registerUser(any(RegisterRequestDTO.class));

        // When & Then
        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void logout_WithValidToken_ShouldReturnSuccess() throws Exception {
        // Given
        String accessToken = "valid-token";
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "test@example.com"
        );

        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);
        // O mock de logoutWithBlacklist já está configurado no setUp()

        // When & Then
        mockMvc.perform(post("/auth/logout")
                .cookie(new jakarta.servlet.http.Cookie("jwt", accessToken))
                .contentType(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));

        verify(authService).validateTokenAndGetUser(accessToken);
        verify(authService).logoutWithBlacklist(eq(accessToken), isNull(), eq("test@example.com"));
    }

    @Test
    void logout_WithRefreshToken_ShouldReturnSuccess() throws Exception {
        // Given
        String refreshToken = "valid-refresh-token";
        Map<String, String> requestBody = Map.of("refreshToken", refreshToken);

        // O mock de logoutWithBlacklist já está configurado no setUp()

        // When & Then
        mockMvc.perform(post("/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));

        verify(authService).logoutWithBlacklist(isNull(), eq(refreshToken), isNull());
    }

    @Test
    void refreshToken_WithValidRefreshToken_ShouldReturnNewToken() throws Exception {
        // Given
        String refreshToken = "valid-refresh-token";
        Map<String, String> requestBody = Map.of("refreshToken", refreshToken);
        Map<String, Object> authData = new HashMap<>();
        authData.put("user", "test@example.com");
        authData.put("role", "USER");
        authData.put("authenticated", true);
        authData.put("accessToken", "new-access-token");

        when(authService.refreshAccessToken(anyString())).thenReturn(authData);
        // Mock já configurado no setUp() - não precisa reconfigurar

        // When & Then
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("test@example.com"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(header().exists("Set-Cookie"));

        verify(authService).refreshAccessToken(refreshToken);
        verify(authService).createAuthCookie(anyString(), any());
    }

    @Test
    void refreshToken_WithInvalidRefreshToken_ShouldReturnUnauthorized() throws Exception {
        // Given
        String refreshToken = "invalid-refresh-token";
        Map<String, String> requestBody = Map.of("refreshToken", refreshToken);

        when(authService.refreshAccessToken(anyString()))
                .thenThrow(new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.UNAUTHORIZED, "Refresh token inválido"));

        // When & Then
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(requestBody)))
                .andDo(print())
                .andExpect(status().isUnauthorized());

        verify(authService).refreshAccessToken(refreshToken);
    }

    @Test
    void checkAuth_WithValidToken_ShouldReturnAuthenticated() throws Exception {
        // Given
        String accessToken = "valid-token";
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "test@example.com",
            "role", "USER"
        );

        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(get("/auth/check")
                .cookie(new jakarta.servlet.http.Cookie("jwt", accessToken)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.user").value("test@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));

        verify(authService).validateTokenAndGetUser(accessToken);
    }

    @Test
    void checkAuth_WithInvalidToken_ShouldReturnUnauthorized() throws Exception {
        // Given
        String accessToken = "invalid-token";
        Map<String, Object> authResult = Map.of(
            "authenticated", false,
            "message", "Token inválido ou expirado"
        );

        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(get("/auth/check")
                .cookie(new jakarta.servlet.http.Cookie("jwt", accessToken)))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.authenticated").value(false))
                .andExpect(jsonPath("$.message").value("Token inválido ou expirado"));

        verify(authService).validateTokenAndGetUser(accessToken);
    }

    @Test
    void checkAuth_WithNoToken_ShouldReturnUnauthorized() throws Exception {
        // Given
        Map<String, Object> authResult = Map.of(
            "authenticated", false,
            "message", "Token não fornecido"
        );

        when(authService.validateTokenAndGetUser(isNull())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(get("/auth/check"))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.authenticated").value(false))
                .andExpect(jsonPath("$.message").value("Token não fornecido"));

        verify(authService).validateTokenAndGetUser(isNull());
    }

    @Test
    void getBlacklistStats_WithAdminToken_ShouldReturnStats() throws Exception {
        // Given
        String adminToken = "admin-token";
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "admin@example.com",
            "role", "ADMIN"
        );

        TokenBlacklistService.BlacklistStats stats = new TokenBlacklistService.BlacklistStats(10, 5) {
            @Override
            public long getActiveBlacklistedTokens() { return 3; }
        };

        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);
        when(tokenBlacklistService.getBlacklistStats()).thenReturn(stats);

        // When & Then
        mockMvc.perform(get("/auth/blacklist/stats")
                .cookie(new jakarta.servlet.http.Cookie("jwt", adminToken)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokensBlacklisted").value(10))
                .andExpect(jsonPath("$.tokensRemoved").value(5))
                .andExpect(jsonPath("$.activeBlacklistedTokens").value(3))
                .andExpect(jsonPath("$.timestamp").exists());

        verify(authService).validateTokenAndGetUser(adminToken);
        verify(tokenBlacklistService).getBlacklistStats();
    }

    @Test
    void getBlacklistStats_WithUserToken_ShouldReturnForbidden() throws Exception {
        // Given
        String userToken = "user-token";
        Map<String, Object> authResult = Map.of(
            "authenticated", true,
            "user", "user@example.com",
            "role", "USER"
        );

        when(authService.validateTokenAndGetUser(anyString())).thenReturn(authResult);

        // When & Then
        mockMvc.perform(get("/auth/blacklist/stats")
                .cookie(new jakarta.servlet.http.Cookie("jwt", userToken)))
                .andDo(print())
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Acesso negado"))
                .andExpect(jsonPath("$.message").value("Apenas administradores podem acessar estatísticas da blacklist"));

        verify(authService).validateTokenAndGetUser(userToken);
        verify(tokenBlacklistService, never()).getBlacklistStats();
    }
}
