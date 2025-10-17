package com.example.loginauthapi.unit.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.domain.UserRole;
import com.example.loginauthapi.infra.security.TokenService;
import com.example.loginauthapi.service.TokenBlacklistService;
import com.example.loginauthapi.config.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenServiceTest {

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private TokenService tokenService;

    private User testUser;

    @BeforeEach
    void setUp() {
        // Configurar JwtProperties mock
        when(jwtProperties.getSecretKey()).thenReturn("test-secret-key-for-testing-only");
        when(jwtProperties.getExpiration()).thenReturn(900000L); // 15 minutos
        when(jwtProperties.getRefreshExpiration()).thenReturn(604800000L); // 7 dias

        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setEmail("test@mail.com");
        testUser.setName("Test User");
        testUser.setRole(UserRole.USER);
    }

    // Testes de Geração de Token (3 testes)

    @Test
    void generateToken_WithValidUser_ShouldReturnValidToken() {
        // When
        String token = tokenService.generateToken(testUser);

        // Then
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3); // JWT tem 3 partes separadas por pontos
    }

    @Test
    void generateRefreshToken_WithValidUser_ShouldReturnValidRefreshToken() {
        // When
        String refreshToken = tokenService.generateRefreshToken(testUser);

        // Then
        assertThat(refreshToken).isNotNull();
        assertThat(refreshToken).isNotEmpty();
        assertThat(refreshToken.split("\\.")).hasSize(3); // JWT tem 3 partes separadas por pontos
    }

    @Test
    void generateTokenPair_WithValidUser_ShouldReturnBothTokens() {
        // When
        Map<String, String> tokenPair = tokenService.generateTokenPair(testUser);

        // Then
        assertThat(tokenPair).isNotNull();
        assertThat(tokenPair).containsKeys("accessToken", "refreshToken");
        assertThat(tokenPair.get("accessToken")).isNotNull();
        assertThat(tokenPair.get("refreshToken")).isNotNull();
        assertThat(tokenPair.get("accessToken")).isNotEqualTo(tokenPair.get("refreshToken"));
    }

    // Testes de Validação de Token (3 testes)

    @Test
    void validateToken_WithValidToken_ShouldReturnEmail() {
        // Given
        String token = tokenService.generateToken(testUser);
        when(tokenBlacklistService.isTokenBlacklisted(token)).thenReturn(false);

        // When
        String result = tokenService.validateToken(token);

        // Then
        assertThat(result).isEqualTo("test@mail.com");
    }

    @Test
    void validateToken_WithBlacklistedToken_ShouldReturnEmpty() {
        // Given
        String token = tokenService.generateToken(testUser);
        when(tokenBlacklistService.isTokenBlacklisted(token)).thenReturn(true);

        // When
        String result = tokenService.validateToken(token);

        // Then
        assertThat(result).isEmpty();
        verify(tokenBlacklistService).isTokenBlacklisted(token);
    }

    @Test
    void validateToken_WithInvalidToken_ShouldReturnEmpty() {
        // Given
        String invalidToken = "invalid.token.here";
        when(tokenBlacklistService.isTokenBlacklisted(invalidToken)).thenReturn(false);

        // When
        String result = tokenService.validateToken(invalidToken);

        // Then
        assertThat(result).isEmpty();
    }

    // Testes de Validação de Refresh Token (2 testes)

    @Test
    void validateRefreshToken_WithValidRefreshToken_ShouldReturnEmail() {
        // Given
        String refreshToken = tokenService.generateRefreshToken(testUser);
        when(tokenBlacklistService.isTokenBlacklisted(refreshToken)).thenReturn(false);

        // When
        String result = tokenService.validateRefreshToken(refreshToken);

        // Then
        assertThat(result).isEqualTo("test@mail.com");
    }

    @Test
    void validateRefreshToken_WithBlacklistedRefreshToken_ShouldReturnEmpty() {
        // Given
        String refreshToken = tokenService.generateRefreshToken(testUser);
        when(tokenBlacklistService.isTokenBlacklisted(refreshToken)).thenReturn(true);

        // When
        String result = tokenService.validateRefreshToken(refreshToken);

        // Then
        assertThat(result).isEmpty();
        verify(tokenBlacklistService).isTokenBlacklisted(refreshToken);
    }
}
