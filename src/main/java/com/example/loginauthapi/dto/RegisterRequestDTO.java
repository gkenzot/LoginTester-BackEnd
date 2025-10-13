// src/main/java/com/example/loginauthapi/dto/RegisterRequestDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(name = "RegisterRequest", description = "Dados necessários para registro")
public record RegisterRequestDTO(
    @Schema(description = "Nome completo", example = "Admin")
    @NotBlank
    String name,
    
    @Schema(description = "Email válido", example = "admin@mail.com")
    @NotBlank
    @Email
    String email,
    
    @Schema(description = "Senha forte com mínimo de 8 caracteres, incluindo maiúscula, minúscula, número e símbolo", example = "MinhaSenh@123")
    @NotBlank(message = "Senha é obrigatória")
    @Size(min = 8, max = 128, message = "Senha deve ter entre 8 e 128 caracteres")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
        message = "Senha deve conter pelo menos: 1 letra minúscula, 1 maiúscula, 1 número e 1 símbolo especial (@$!%*?&)"
    )
    String password,
    
    @Schema(description = "Confirmação da senha", example = "MinhaSenh@123")
    @NotBlank(message = "Confirmação de senha é obrigatória")
    String confirmPassword
) {}