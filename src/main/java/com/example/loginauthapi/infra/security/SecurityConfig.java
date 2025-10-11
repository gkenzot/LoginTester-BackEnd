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

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final SecurityFilter securityFilter;

	public SecurityConfig(SecurityFilter securityFilter) {
		this.securityFilter = securityFilter;
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			// Configuração CORS que aceita qualquer origem (incluindo ngrok)
			.cors(cors -> cors.configurationSource(request -> {
				var config = new org.springframework.web.cors.CorsConfiguration();
				
				// Aceita qualquer origem usando padrão (funciona com ngrok e outros domínios)
				config.addAllowedOriginPattern("*");
				
				config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
				config.setAllowedHeaders(Arrays.asList("*"));
				config.setAllowCredentials(true);
				config.setMaxAge(3600L);
				
				return config;
			}))
			
			// Configuração CSRF (desabilitado para APIs stateless)
			.csrf(csrf -> csrf.disable())
			
			// Gerenciamento de Sessão
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)
			
			// Autorizações
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/auth/**").permitAll()
				.requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**", "/swagger-resources/**", "/webjars/**").permitAll()
				.requestMatchers("OPTIONS", "/**").permitAll() // Permite todas as requisições OPTIONS
				.anyRequest().authenticated()
			)
			
			// Adiciona o filtro de segurança
			.addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}