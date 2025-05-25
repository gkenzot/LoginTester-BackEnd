package com.example.loginauthapi.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.lang.NonNull;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        var token = recoverToken(request);
        
        if (token != null) {
            var email = tokenService.validateToken(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);
            
            var authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
                
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    private String recoverToken(HttpServletRequest request) {
        // 1. Tentar recuperar do cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("jwt")) {
                    return cookie.getValue();
                }
            }
        }
        
        // 2. Fallback para header Authorization (opcional)
        var authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            return authHeader.replace("Bearer ", "");
        }
        
        return null;
    }
}