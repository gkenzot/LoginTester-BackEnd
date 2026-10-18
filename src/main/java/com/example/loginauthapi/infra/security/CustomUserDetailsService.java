// src/main/java/com/example/loginauthapi/infra/security/CustomUserDetailsService.java
package com.example.loginauthapi.infra.security;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.repositories.UserRepository;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final MessageSource messageSource;

    public CustomUserDetailsService(UserRepository userRepository, MessageSource messageSource) {
        this.userRepository = userRepository;
        this.messageSource = messageSource;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> {
                Locale locale = LocaleContextHolder.getLocale() != null ? LocaleContextHolder.getLocale() : Locale.forLanguageTag("pt-BR");
                String message = messageSource.getMessage("error.user.notfound", null, locale);
                return new UsernameNotFoundException(message);
            });
        return user;
    }
}