// src/main/java/com/example/loginauthapi/infra/security/SecurityConfig.java
package com.example.loginauthapi.infra.security;

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

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final SecurityFilter securityFilter;

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
	        .cors(cors -> cors.configurationSource(corsConfigurationSource))
	        
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
	                "/v3/api-docs/**"
	            ).permitAll()
	            
	            // Todas outras requisições exigem autenticação
	            .anyRequest().authenticated()
	        )
	        
	        // Filtros customizados
	        .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);
	    
	    return http.build();
	}
	
//	@Bean
//	SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource)
//			throws Exception {
//		return http
//				.csrf(csrf -> csrf.disable())
//				.cors(cors -> cors.configurationSource(corsConfigurationSource))
//				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//				.authorizeHttpRequests(authorize -> authorize.requestMatchers("/auth/**")
//						.permitAll()
//						.requestMatchers(
//								"/swagger-ui.html",
//								"/swagger-ui/**",
//								"/v3/api-docs/**"
//								)
//						.permitAll()
//						.anyRequest()
//						.authenticated())
//				.addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class).build();
//	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}