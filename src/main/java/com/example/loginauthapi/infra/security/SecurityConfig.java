// src/main/java/com/example/loginauthapi/infra/security/SecurityConfig.java
package com.example.loginauthapi.infra.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final SecurityFilter securityFilter;

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

	public SecurityConfig(SecurityFilter securityFilter) {
		this.securityFilter = securityFilter;
	}

	@Bean
	SecurityFilterChain securityFilterChain(
	    HttpSecurity http,
	    CorsConfigurationSource corsConfigurationSource
	) throws Exception {
	    http
	        // Configuração CORS
	        .cors(cors -> cors.configurationSource(request -> {
	            var corsConfig = new org.springframework.web.cors.CorsConfiguration();
	            corsConfig.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
	            corsConfig.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
	            corsConfig.setAllowedHeaders(Arrays.asList(allowedHeaders.split(",")));
	            corsConfig.setAllowCredentials(allowCredentials);
	            corsConfig.setMaxAge(maxAge);
	            return corsConfig;
	        }))
	        
	        // Configuração CSRF (desabilitado para APIs stateless)
	        .csrf(csrf -> csrf.disable())
	        
	        // Gerenciamento de Sessão
	        .sessionManagement(session -> session
	            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	        )
	        
	        // Autorizações
	        .authorizeHttpRequests(auth -> auth
	            // Libera endpoints públicos
	            .requestMatchers(
	                "/auth/**",
	                "/swagger-ui.html",
	                "/swagger-ui/**",
	                "/v3/api-docs/**",
	                "/swagger-resources/**",
	                "/webjars/**"
	            ).permitAll()
	            
	            // Todas outras requisições exigem autenticação
	            .anyRequest().authenticated()
	        )
	        
	        // Filtros customizados
	        .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);
	    
	    return http.build();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}