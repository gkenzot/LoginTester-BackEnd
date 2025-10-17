package com.example.loginauthapi.controller;

import com.example.loginauthapi.dto.*;
import com.example.loginauthapi.service.PasswordResetCodeService;
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
@Tag(name = "Password Reset Code", description = "Endpoints para recuperação de senha com código")
public class PasswordResetCodeController {
    
    private final PasswordResetCodeService passwordResetCodeService;
    
    @PostMapping("/send-reset-code")
    @Operation(summary = "Enviar código de reset", description = "Envia código de 6 dígitos para redefinir senha")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Código enviado com sucesso"),
            @ApiResponse(responseCode = "400", description = "Dados inválidos"),
            @ApiResponse(responseCode = "404", description = "Email não encontrado"),
            @ApiResponse(responseCode = "429", description = "Muitas tentativas")
    })
    public ResponseEntity<Map<String, String>> sendResetCode(@Valid @RequestBody SendResetCodeRequest request) {
        try {
            passwordResetCodeService.sendResetCode(request);
            return ResponseEntity.ok(Map.of("message", "Código de redefinição enviado com sucesso"));
        } catch (RuntimeException e) {
            log.error("Error sending reset code: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/verify-reset-code")
    @Operation(summary = "Verificar código de reset", description = "Verifica se o código de 6 dígitos é válido")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Código válido"),
            @ApiResponse(responseCode = "400", description = "Código inválido ou expirado")
    })
    public ResponseEntity<Map<String, Object>> verifyResetCode(@Valid @RequestBody VerifyResetCodeRequest request) {
        try {
            boolean isValid = passwordResetCodeService.verifyResetCode(request);
            return ResponseEntity.ok(Map.of("valid", isValid));
        } catch (RuntimeException e) {
            log.error("Error verifying reset code: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/reset-password-with-code")
    @Operation(summary = "Redefinir senha com código", description = "Redefine a senha usando o código de 6 dígitos")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Senha redefinida com sucesso"),
            @ApiResponse(responseCode = "400", description = "Código inválido ou senhas não coincidem")
    })
    public ResponseEntity<Map<String, String>> resetPasswordWithCode(@Valid @RequestBody ResetPasswordWithCodeRequest request) {
        try {
            passwordResetCodeService.resetPasswordWithCode(request);
            return ResponseEntity.ok(Map.of("message", "Senha redefinida com sucesso"));
        } catch (RuntimeException e) {
            log.error("Error resetting password with code: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
