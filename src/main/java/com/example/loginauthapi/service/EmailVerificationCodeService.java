package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.EmailVerificationCode;
import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.SendEmailVerificationCodeRequest;
import com.example.loginauthapi.dto.VerifyEmailCodeRequest;
import com.example.loginauthapi.repositories.EmailVerificationCodeRepository;
import com.example.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class EmailVerificationCodeService {

    private final UserRepository userRepository;
    private final EmailVerificationCodeRepository codeRepository;
    private final EmailService emailService;

    private static final int CODE_EXPIRATION_MINUTES = 10;
    private static final int MAX_ATTEMPTS = 3;
    private static final int MAX_CODES_PER_HOUR = 3;

    @Transactional
    public void sendVerificationCode(SendEmailVerificationCodeRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        // Verificar se o usuário já está verificado
        if (user.getRole() != com.example.loginauthapi.domain.UserRole.UNVERIFIED) {
            throw new RuntimeException("Usuário já verificado");
        }

        // Verificar limite de códigos por hora
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
        long codesInLastHour = codeRepository.countByUserAndCreatedAtAfter(user.getId(), oneHourAgo);
        if (codesInLastHour >= MAX_CODES_PER_HOUR) {
            throw new RuntimeException("Muitas solicitações de código. Tente novamente mais tarde.");
        }

        // Invalidar códigos anteriores não utilizados para o mesmo usuário
        codeRepository.deleteAllByUser(user);

        String code = generateRandomCode();
        EmailVerificationCode verificationCode = EmailVerificationCode.builder()
                .code(code)
                .user(user)
                .expiresAt(LocalDateTime.now().plusMinutes(CODE_EXPIRATION_MINUTES))
                .used(false)
                .attempts(0)
                .build();

        codeRepository.save(verificationCode);
        emailService.sendEmailVerificationCode(user.getEmail(), code, user.getName());
        log.info("Email verification code sent successfully to user: {}", user.getEmail());
    }

    @Transactional
    public void verifyEmailCode(VerifyEmailCodeRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        EmailVerificationCode verificationCode = codeRepository.findByUserAndCodeAndUsedFalseAndExpiresAtAfter(
                        user, request.getCode(), LocalDateTime.now())
                .orElseThrow(() -> new RuntimeException("Código inválido ou expirado"));

        if (verificationCode.getAttempts() >= MAX_ATTEMPTS - 1) { // -1 porque incrementamos antes de verificar
            verificationCode.setUsed(true); // Invalida o código após muitas tentativas
            codeRepository.save(verificationCode);
            throw new RuntimeException("Muitas tentativas. Código inválido.");
        }
        verificationCode.incrementAttempts();
        codeRepository.save(verificationCode);

        if (!verificationCode.isValid()) {
            throw new RuntimeException("Código inválido ou expirado");
        }

        // Atualizar usuário para USER
        user.setRole(com.example.loginauthapi.domain.UserRole.USER);
        userRepository.save(user);

        // Marcar código como usado
        verificationCode.setUsed(true);
        codeRepository.save(verificationCode);
        
        log.info("Email verified successfully for user: {}", user.getEmail());
    }

    private String generateRandomCode() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(999999));
    }
}
