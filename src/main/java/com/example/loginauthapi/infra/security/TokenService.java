// src/main/java/com/example/loginauthapi/infra/security/TokenService.java
package com.example.loginauthapi.infra.security;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.service.TokenBlacklistService;
import com.example.loginauthapi.config.JwtProperties;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);
    
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtProperties jwtProperties;
    
    public String generateToken(User user) {
        logger.debug("Generating access token for user: {}", user.getEmail());
        
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtProperties.getSecretKey());
            Instant expirationDate = genAccessTokenExpirationDate();
            
            String token = JWT.create()
                .withIssuer("login-auth-api")
                .withSubject(user.getEmail())
                .withClaim("type", "access")
                .withClaim("userId", user.getId().toString())
                .withExpiresAt(expirationDate)
                .sign(algorithm);
            
            logger.debug("Access token generated successfully for user: {}", user.getEmail());
            return token;
        } catch (JWTCreationException exception) {
            logger.error("Error generating access token: {}", exception.getMessage(), exception);
            throw new RuntimeException("Error while generating access token", exception);
        } catch (Exception e) {
            logger.error("Unexpected error generating access token: {}", e.getMessage(), e);
            throw e;
        }
    }
    
    public String generateRefreshToken(User user) {
        logger.debug("Generating refresh token for user: {}", user.getEmail());
        
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtProperties.getSecretKey());
            Instant expirationDate = genRefreshTokenExpirationDate();
            String tokenId = UUID.randomUUID().toString();
            
            String refreshToken = JWT.create()
                .withIssuer("login-auth-api")
                .withSubject(user.getEmail())
                .withClaim("type", "refresh")
                .withClaim("userId", user.getId().toString())
                .withClaim("tokenId", tokenId)
                .withExpiresAt(expirationDate)
                .sign(algorithm);
            
            logger.debug("Refresh token generated successfully for user: {}", user.getEmail());
            return refreshToken;
        } catch (JWTCreationException exception) {
            logger.error("Error generating refresh token: {}", exception.getMessage(), exception);
            throw new RuntimeException("Error while generating refresh token", exception);
        } catch (Exception e) {
            logger.error("Unexpected error generating refresh token: {}", e.getMessage(), e);
            throw e;
        }
    }
    
    public Map<String, String> generateTokenPair(User user) {
        String accessToken = generateToken(user);
        String refreshToken = generateRefreshToken(user);
        
        Map<String, String> tokenPair = new HashMap<>();
        tokenPair.put("accessToken", accessToken);
        tokenPair.put("refreshToken", refreshToken);
        return tokenPair;
    }
    
    public String validateToken(String token) {
        logger.debug("Validating token: {}", token != null ? "[PRESENT]" : "[NULL]");
        
        try {
            // ✅ Verificar se token está na blacklist primeiro
            if (token != null && tokenBlacklistService.isTokenBlacklisted(token)) {
                logger.warn("Token is blacklisted: {}", token.substring(0, Math.min(20, token.length())) + "...");
                return "";
            }
            
            Algorithm algorithm = Algorithm.HMAC256(jwtProperties.getSecretKey());
            
            DecodedJWT decodedJWT = JWT.require(algorithm)
                .withIssuer("login-auth-api")
                .build()
                .verify(token);
            
            // Verificar se é um access token
            String tokenType = decodedJWT.getClaim("type").asString();
            if (!"access".equals(tokenType)) {
                logger.debug("Invalid token type: {}", tokenType);
                return "";
            }
            
            String subject = decodedJWT.getSubject();
            logger.debug("Token validated successfully for subject: {}", subject);
            return subject;
        } catch (JWTVerificationException exception) {
            logger.debug("Invalid or expired token: {}", exception.getMessage());
            return "";
        } catch (Exception e) {
            logger.error("Unexpected error during token validation: {}", e.getMessage(), e);
            return "";
        }
    }
    
    public String validateRefreshToken(String refreshToken) {
        logger.debug("Validating refresh token: {}", refreshToken != null ? "[PRESENT]" : "[NULL]");
        
        try {
            // ✅ Verificar se refresh token está na blacklist primeiro
            if (refreshToken != null && tokenBlacklistService.isTokenBlacklisted(refreshToken)) {
                logger.warn("Refresh token is blacklisted: {}", refreshToken.substring(0, Math.min(20, refreshToken.length())) + "...");
                return "";
            }
            
            Algorithm algorithm = Algorithm.HMAC256(jwtProperties.getSecretKey());
            
            DecodedJWT decodedJWT = JWT.require(algorithm)
                .withIssuer("login-auth-api")
                .build()
                .verify(refreshToken);
            
            // Verificar se é um refresh token
            String tokenType = decodedJWT.getClaim("type").asString();
            if (!"refresh".equals(tokenType)) {
                logger.debug("Invalid refresh token type: {}", tokenType);
                return "";
            }
            
            String subject = decodedJWT.getSubject();
            logger.debug("Refresh token validated successfully for subject: {}", subject);
            return subject;
        } catch (JWTVerificationException exception) {
            logger.debug("Invalid or expired refresh token: {}", exception.getMessage());
            return "";
        } catch (Exception e) {
            logger.error("Unexpected error during refresh token validation: {}", e.getMessage(), e);
            return "";
        }
    }
    
    private Instant genAccessTokenExpirationDate() {
        // Access token: usar configuração de JWT properties
        long expirationMs = jwtProperties.getExpiration();
        return LocalDateTime.now(ZoneOffset.UTC)
                .plusSeconds(expirationMs / 1000)
                .toInstant(ZoneOffset.UTC);
    }
    
    private Instant genRefreshTokenExpirationDate() {
        // Refresh token: usar configuração de JWT properties
        long refreshExpirationMs = jwtProperties.getRefreshExpiration();
        return LocalDateTime.now(ZoneOffset.UTC)
                .plusSeconds(refreshExpirationMs / 1000)
                .toInstant(ZoneOffset.UTC);
    }
}