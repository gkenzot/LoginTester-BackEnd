package com.example.loginauthapi.controller;

import com.example.loginauthapi.dto.SendEmailVerificationCodeRequest;
import com.example.loginauthapi.dto.VerifyEmailCodeRequest;
import com.example.loginauthapi.dto.VerifyEmailRequest;
import com.example.loginauthapi.service.EmailVerificationCodeService;
import com.example.loginauthapi.service.EmailVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Endpoints de autenticação")
public class EmailVerificationController {
    
    private final EmailVerificationService emailVerificationService;
    private final EmailVerificationCodeService emailVerificationCodeService;
    
    @PostMapping("/verify-email")
    @Operation(summary = "Verificar email", description = "Verifica o email usando o token recebido")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email verificado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Token inválido ou expirado")
    })
    public ResponseEntity<Map<String, String>> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        try {
            emailVerificationService.verifyEmail(request);
            return ResponseEntity.ok(Map.of("message", "Email verificado com sucesso"));
        } catch (RuntimeException e) {
            log.error("Error in email verification: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/send-email-verification-code")
    @Operation(summary = "Enviar código de verificação", description = "Envia código de 6 dígitos para verificar email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Código enviado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Erro ao enviar código")
    })
    public ResponseEntity<String> sendEmailVerificationCode(@RequestBody @Valid SendEmailVerificationCodeRequest request) {
        try {
            emailVerificationCodeService.sendVerificationCode(request);
            return ResponseEntity.ok("Código de verificação enviado com sucesso para o seu email.");
        } catch (RuntimeException e) {
            log.error("Erro ao enviar código de verificação: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/verify-email-code")
    @Operation(summary = "Verificar código de email", description = "Verifica o código de 6 dígitos e ativa a conta")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email verificado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Código inválido ou expirado")
    })
    public ResponseEntity<String> verifyEmailCode(@RequestBody @Valid VerifyEmailCodeRequest request) {
        try {
            emailVerificationCodeService.verifyEmailCode(request);
            return ResponseEntity.ok("Email verificado com sucesso. Sua conta foi ativada!");
        } catch (RuntimeException e) {
            log.error("Erro ao verificar código de email: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    @GetMapping("/validate-verification-token")
    @Operation(summary = "Validar token de verificação", description = "Verifica se o token de verificação é válido")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token válido"),
            @ApiResponse(responseCode = "400", description = "Token inválido")
    })
    public ResponseEntity<Map<String, Object>> validateVerificationToken(@RequestParam String token) {
        boolean isValid = emailVerificationService.validateVerificationToken(token);
        return ResponseEntity.ok(Map.of("valid", isValid));
    }
}
