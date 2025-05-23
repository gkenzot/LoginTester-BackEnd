// src/main/java/com/example/loginauthapi/dto/UpdatePasswordDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasswordDTO(
	@Schema(description = "Senha atual", example = "123456")
    @NotBlank(message = "Current password cannot be blank")
    String currentPassword,
    
    @Schema(description = "Senha nova 01", example = "abcdef")
    @NotBlank(message = "New password cannot be blank")
    @Size(min = 8, message = "New password must be at least 8 characters long")
    String newPassword,
    
    @Schema(description = "Senha nova 02", example = "abcdef")
    @NotBlank(message = "Password confirmation cannot be blank")
    String confirmPassword
) {
    public boolean passwordsMatch() {
        return newPassword.equals(confirmPassword);
    }
}