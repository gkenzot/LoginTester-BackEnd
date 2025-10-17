package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.PasswordResetCode;
import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.*;
import com.example.loginauthapi.repositories.PasswordResetCodeRepository;
import com.example.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;
import java.util.List;
import java.util.ArrayList;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PasswordResetCodeService {
    
    private final UserRepository userRepository;
    private final PasswordResetCodeRepository codeRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    
    private static final int CODE_EXPIRATION_MINUTES = 10; // Código expira em 10 minutos
    private static final int MAX_ATTEMPTS = 3;
    private static final int MAX_CODES_PER_HOUR = 3;
    
    public void sendResetCode(SendResetCodeRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email não encontrado"));
        
        // Verificar limite de códigos por hora
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        long codesInLastHour = codeRepository.countByUserAndCreatedAtAfter(user.getId(), oneHourAgo);
        
        if (codesInLastHour >= MAX_CODES_PER_HOUR) {
            throw new RuntimeException("Muitas tentativas. Aguarde 1 hora antes de solicitar um novo código.");
        }
        
        // Deletar códigos anteriores do usuário
        codeRepository.deleteByUser(user);
        
        // Gerar código de 6 dígitos
        String code = generateSixDigitCode();
        
        // Criar novo código
        PasswordResetCode resetCode = PasswordResetCode.builder()
                .code(code)
                .user(user)
                .expiresAt(LocalDateTime.now().plusMinutes(CODE_EXPIRATION_MINUTES))
                .used(false)
                .attempts(0)
                .build();
        
        codeRepository.save(resetCode);
        
        // Enviar email
        emailService.sendPasswordResetCode(user.getEmail(), code, user.getName());
        
        log.info("Password reset code sent to user: {}", user.getEmail());
    }
    
    public boolean verifyResetCode(VerifyResetCodeRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email não encontrado"));
        
        PasswordResetCode resetCode = codeRepository.findByCodeAndUser(request.getCode(), user)
                .orElseThrow(() -> new RuntimeException("Código inválido"));
        
        // Incrementar tentativas
        resetCode.incrementAttempts();
        codeRepository.save(resetCode);
        
        // Verificar se o código é válido
        if (!resetCode.isValid()) {
            if (resetCode.isExpired()) {
                throw new RuntimeException("Código expirado");
            } else if (resetCode.getAttempts() >= MAX_ATTEMPTS) {
                throw new RuntimeException("Muitas tentativas incorretas. Solicite um novo código.");
            } else {
                throw new RuntimeException("Código inválido");
            }
        }
        
        log.info("Password reset code verified for user: {}", user.getEmail());
        return true;
    }
    
    public void resetPasswordWithCode(ResetPasswordWithCodeRequest request) {
        // Validar senhas
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new RuntimeException("Senhas não coincidem");
        }
        
        // Validar força da senha
        validatePasswordStrength(request.getNewPassword());
        
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email não encontrado"));
        
        PasswordResetCode resetCode = codeRepository.findByCodeAndUser(request.getCode(), user)
                .orElseThrow(() -> new RuntimeException("Código inválido"));
        
        // Validar código
        if (!resetCode.isValid()) {
            if (resetCode.isExpired()) {
                throw new RuntimeException("Código expirado");
            } else if (resetCode.getAttempts() >= MAX_ATTEMPTS) {
                throw new RuntimeException("Muitas tentativas incorretas. Solicite um novo código.");
            } else {
                throw new RuntimeException("Código inválido");
            }
        }
        
        // Atualizar senha
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        
        // Marcar código como usado
        resetCode.markAsUsed();
        codeRepository.save(resetCode);
        
        log.info("Password reset successfully with code for user: {}", user.getEmail());
    }
    
    private String generateSixDigitCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000); // Gera número entre 100000 e 999999
        return String.valueOf(code);
    }
    
    /**
     * Valida a força da senha com critérios específicos
     */
    private void validatePasswordStrength(String password) {
        List<String> errors = new ArrayList<>();
        
        if (password == null || password.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Senha é obrigatória");
        }
        
        if (password.length() < 8) {
            errors.add("Senha deve ter pelo menos 8 caracteres");
        }
        
        if (password.length() > 128) {
            errors.add("Senha deve ter no máximo 128 caracteres");
        }
        
        if (!password.matches(".*[a-z].*")) {
            errors.add("Senha deve conter pelo menos uma letra minúscula");
        }
        
        if (!password.matches(".*[A-Z].*")) {
            errors.add("Senha deve conter pelo menos uma letra maiúscula");
        }
        
        if (!password.matches(".*\\d.*")) {
            errors.add("Senha deve conter pelo menos um número");
        }
        
        if (!password.matches(".*[@$!%*?&].*")) {
            errors.add("Senha deve conter pelo menos um símbolo especial (@$!%*?&)");
        }
        
        // Verifica se contém apenas espaços em branco
        if (password.trim().isEmpty()) {
            errors.add("Senha não pode conter apenas espaços");
        }
        
        // Verifica senhas comuns fracas
        String[] commonPasswords = {"123456", "password", "123456789", "12345678", "12345", 
                                   "1234567", "1234567890", "qwerty", "abc123", "password123"};
        for (String common : commonPasswords) {
            if (password.toLowerCase().contains(common.toLowerCase())) {
                errors.add("Senha muito comum. Escolha uma senha mais segura");
                break;
            }
        }
        
        if (!errors.isEmpty()) {
            String errorMessage = "Senha não atende aos critérios de segurança: " + String.join(", ", errors);
            log.warn("Password validation failed: {}", errorMessage);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, errorMessage);
        }
    }
}
