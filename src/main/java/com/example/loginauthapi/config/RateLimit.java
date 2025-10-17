package com.example.loginauthapi.config;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotação para aplicar Rate Limiting em endpoints
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {
    
    /**
     * Tipo de endpoint para aplicar o limite correto
     */
    EndpointType value();
    
    enum EndpointType {
        LOGIN,      // 5 tentativas por minuto
        REGISTER,    // 10 tentativas por hora (ajustado para testes)
        CHECK        // 60 tentativas por minuto
    }
}
