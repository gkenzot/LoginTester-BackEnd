// src/main/java/com/example/loginauthapi/dto/UpdateUserDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public record UpdateUserDTO(
	@Schema(description = "Nome", example = "Admin edited")
    @NotBlank(message = "O nome não pode estar vazio")
    String name
) {}