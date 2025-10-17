package com.example.loginauthapi.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Propriedades de configuração JWT
 * 
 * Centraliza todas as configurações relacionadas ao JWT em um único lugar
 */
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    
    private String secretKey;
    private Long expiration = 900000L; // 15 minutos padrão
    private Long refreshExpiration = 604800000L; // 7 dias padrão
    
    public String getSecretKey() {
        return secretKey;
    }
    
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
    
    public Long getExpiration() {
        return expiration;
    }
    
    public void setExpiration(Long expiration) {
        this.expiration = expiration;
    }
    
    public Long getRefreshExpiration() {
        return refreshExpiration;
    }
    
    public void setRefreshExpiration(Long refreshExpiration) {
        this.refreshExpiration = refreshExpiration;
    }
    
    @Override
    public String toString() {
        return "JwtProperties{" +
                "secretKey='" + (secretKey != null ? "[SET]" : "[NOT_SET]") + '\'' +
                ", expiration=" + expiration +
                ", refreshExpiration=" + refreshExpiration +
                '}';
    }
}
