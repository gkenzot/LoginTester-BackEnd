package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.EmailVerificationToken;
import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.VerifyEmailRequest;
import com.example.loginauthapi.repositories.EmailVerificationTokenRepository;
import com.example.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class EmailVerificationService {
    
    private final UserRepository userRepository;
    private final EmailVerificationTokenRepository tokenRepository;
    private final EmailService emailService;
    
    public void sendVerificationEmail(User user) {
        // Deletar tokens anteriores do usuário
        tokenRepository.deleteByUserId(user.getId());
        
        // Criar novo token
        String token = UUID.randomUUID().toString();
        EmailVerificationToken verificationToken = EmailVerificationToken.builder()
                .token(token)
                .user(user)
                .expiresAt(LocalDateTime.now().plusHours(24)) // Expira em 24 horas
                .used(false)
                .build();
        
        tokenRepository.save(verificationToken);
        
        // Enviar email
        emailService.sendEmailVerificationEmail(user.getEmail(), token, user.getName());
        
        log.info("Email verification token created for user: {}", user.getEmail());
    }
    
    public void verifyEmail(VerifyEmailRequest request) {
        // Buscar token
        EmailVerificationToken verificationToken = tokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Token inválido"));
        
        // Validar token
        if (!verificationToken.isValid()) {
            throw new RuntimeException("Token expirado ou já utilizado");
        }
        
        // Atualizar usuário
        User user = verificationToken.getUser();
        user.setRole(com.example.loginauthapi.domain.UserRole.USER); // Mudar de UNVERIFIED para USER
        userRepository.save(user);
        
        // Marcar token como usado
        verificationToken.setUsed(true);
        tokenRepository.save(verificationToken);
        
        log.info("Email verified successfully for user: {}", user.getEmail());
    }
    
    public boolean validateVerificationToken(String token) {
        return tokenRepository.findByToken(token)
                .map(EmailVerificationToken::isValid)
                .orElse(false);
    }
}
