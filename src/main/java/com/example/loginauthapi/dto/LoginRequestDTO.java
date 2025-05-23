// src/main/java/com/example/loginauthapi/dto/LoginRequestDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "LoginRequest", description = "Dados necessários para autenticação")
public record LoginRequestDTO(
    @Schema(description = "Email do usuário", example = "admin@mail.com")
    String email,
    
    @Schema(description = "Senha do usuário", example = "123456")
    String password
) {}