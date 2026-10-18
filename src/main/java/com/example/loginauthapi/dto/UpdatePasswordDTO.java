// src/main/java/com/example/loginauthapi/dto/UpdatePasswordDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasswordDTO(
	@Schema(description = "Senha atual", example = "123456")
    @NotBlank(message = "Senha atual é obrigatória")
    String currentPassword,
    
    @Schema(description = "Senha nova 01", example = "abcdef")
    @NotBlank(message = "Nova senha é obrigatória")
    @Size(min = 8, message = "Nova senha deve ter pelo menos 8 caracteres")
    String newPassword,
    
    @Schema(description = "Senha nova 02", example = "abcdef")
    @NotBlank(message = "Confirmação de senha é obrigatória")
    String confirmPassword
) {
    public boolean passwordsMatch() {
        return newPassword.equals(confirmPassword);
    }
}