package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.PasswordResetToken;
import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.ForgotPasswordRequest;
import com.example.loginauthapi.dto.ResetPasswordRequest;
import com.example.loginauthapi.repositories.PasswordResetTokenRepository;
import com.example.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PasswordResetService {
    
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    
    public void requestPasswordReset(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email não encontrado"));
        
        // Deletar tokens anteriores do usuário
        tokenRepository.deleteByUserId(user.getId());
        
        // Criar novo token
        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .user(user)
                .expiresAt(LocalDateTime.now().plusHours(1)) // Expira em 1 hora
                .used(false)
                .build();
        
        tokenRepository.save(resetToken);
        
        // Enviar email (método antigo mantido para compatibilidade)
        // emailService.sendPasswordResetEmail(user.getEmail(), token, user.getName());
        
        log.info("Password reset token created for user: {}", user.getEmail());
    }
    
    public void resetPassword(ResetPasswordRequest request) {
        // Validar senhas
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new RuntimeException("Senhas não coincidem");
        }
        
        // Buscar token
        PasswordResetToken resetToken = tokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Token inválido"));
        
        // Validar token
        if (!resetToken.isValid()) {
            throw new RuntimeException("Token expirado ou já utilizado");
        }
        
        // Atualizar senha
        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        
        // Marcar token como usado
        resetToken.setUsed(true);
        tokenRepository.save(resetToken);
        
        log.info("Password reset successfully for user: {}", user.getEmail());
    }
    
    public boolean validateResetToken(String token) {
        return tokenRepository.findByToken(token)
                .map(PasswordResetToken::isValid)
                .orElse(false);
    }
}
