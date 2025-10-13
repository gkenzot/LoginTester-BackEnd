// src/main/java/com/example/loginauthapi/infra/security/TokenService.java
package com.example.loginauthapi.infra.security;

import com.example.loginauthapi.domain.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);
    
    @Value("${jwt.secret-key}")
    private String secretKey;
    
    @Value("${jwt.expiration}")
    private Long expiration;
    
    public String generateToken(User user) {
        logger.debug("Generating token for user: {}", user.getEmail());
        
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            Instant expirationDate = genExpirationDate();
            
            String token = JWT.create()
                .withIssuer("login-auth-api")
                .withSubject(user.getEmail())
                .withExpiresAt(expirationDate)
                .sign(algorithm);
            
            logger.debug("Token generated successfully for user: {}", user.getEmail());
            return token;
        } catch (JWTCreationException exception) {
            logger.error("Error generating token: {}", exception.getMessage(), exception);
            throw new RuntimeException("Error while generating token", exception);
        } catch (Exception e) {
            logger.error("Unexpected error generating token: {}", e.getMessage(), e);
            throw e;
        }
    }
    
    public String validateToken(String token) {
        logger.debug("Validating token: {}", token != null ? "[PRESENT]" : "[NULL]");
        
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            
            String subject = JWT.require(algorithm)
                .withIssuer("login-auth-api")
                .build()
                .verify(token)
                .getSubject();
            
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
    
    private Instant genExpirationDate() {
        return LocalDateTime.now(ZoneOffset.UTC).plusHours(24).toInstant(ZoneOffset.UTC);
    }
}