package com.example.loginauthapi.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {
	
	@Value("${app.cors.allowed-origins}")
	private String allowedOrigins;

	@Value("${app.cors.allowed-methods}")
	private String allowedMethods;

	@Value("${app.cors.allowed-headers}")
	private String allowedHeaders;

	@Value("${app.cors.allow-credentials}")
	private boolean allowCredentials;

	@Value("${app.cors.max-age}")
	private long maxAge;

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
	    CorsConfiguration configuration = new CorsConfiguration();
	    
	    // Configuração das origens permitidas
	    List<String> origins = Arrays.asList(allowedOrigins.split(","));
	    configuration.setAllowedOrigins(origins);
	    
	    // Configuração dos métodos HTTP permitidos
	    List<String> methods = Arrays.asList(allowedMethods.split(","));
	    configuration.setAllowedMethods(methods);
	    
	    // Configuração dos headers permitidos
	    List<String> headers = Arrays.asList(allowedHeaders.split(","));
	    configuration.setAllowedHeaders(headers);
	    
	    // Headers expostos
	    configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type"));
	    
	    // Configuração de credenciais
	    configuration.setAllowCredentials(allowCredentials);
	    
	    // Tempo máximo de cache da configuração CORS
	    configuration.setMaxAge(maxAge);
	    
	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    source.registerCorsConfiguration("/**", configuration);
	    
	    return source;
	}
}
