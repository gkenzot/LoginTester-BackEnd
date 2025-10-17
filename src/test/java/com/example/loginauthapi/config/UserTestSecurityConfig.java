package com.example.loginauthapi.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@TestConfiguration
public class UserTestSecurityConfig {

    @Bean
    public SecurityFilterChain userTestSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for testing
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").permitAll() // Permit all user requests for testing
                .anyRequest().permitAll() // Permit all other requests for testing purposes
            );
        return http.build();
    }
}
