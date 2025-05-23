// src/main/java/com/example/loginauthapi/dto/RegisterRequestDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
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
    
    @Schema(description = "Senha com mínimo de 6 caracteres", example = "123456")
    @NotBlank
    @Size(min = 3)
    String password
) {}