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
	private final CorsConfigurationSource corsConfigurationSource;

	public SecurityConfig(SecurityFilter securityFilter, CorsConfigurationSource corsConfigurationSource) {
		this.securityFilter = securityFilter;
		this.corsConfigurationSource = corsConfigurationSource;
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/auth/**", "/auth/login").permitAll()
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