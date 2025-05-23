package com.example.loginauthapi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {
	
	@Bean
	@Primary
	CorsConfigurationSource corsConfigurationSource() {
	    CorsConfiguration configuration = new CorsConfiguration();
	    
	    // Origens controladas (evite "*" em produção)
	    configuration.setAllowedOrigins(List.of(
	        "http://localhost:5173",
	        "https://seusite.com" // Adicione seu domínio de produção
	    ));
	    
	    // Métodos específicos
	    configuration.setAllowedMethods(List.of(
	        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
	    ));
	    
	    // Headers explícitos
	    configuration.setAllowedHeaders(List.of(
	        "Authorization",
	        "Content-Type",
	        "X-Requested-With",
	        "Accept",
	        "Origin"
	    ));
	    
	    // Headers expostos para o frontend
	    configuration.setExposedHeaders(List.of(
	        "Authorization",
	        "X-Custom-Header"
	    ));
	    
	    configuration.setAllowCredentials(true);
	    configuration.setMaxAge(3600L); // Cache de 1 hora
	    
	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    source.registerCorsConfiguration("/**", configuration);
	    return source;
	}
}
