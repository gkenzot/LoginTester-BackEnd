package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "RefreshTokenRequest", description = "Refresh token para renovar o access token")
public record RefreshTokenRequestDTO(
    @NotBlank(message = "Refresh token é obrigatório")
    @Schema(description = "Refresh token JWT", requiredMode = Schema.RequiredMode.REQUIRED)
    String refreshToken
) {}
