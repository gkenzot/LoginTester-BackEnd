// src/main/java/com/example/loginauthapi/dto/LoginResponseDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "LoginResponse", description = "Token JWT retornado após login bem-sucedido")
public record LoginResponseDTO(
    @Schema(description = "Token JWT para autenticação", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    String token
) {}