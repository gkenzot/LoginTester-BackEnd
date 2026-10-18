// src/main/java/com/example/loginauthapi/dto/UpdateUserDTO.java
package com.example.loginauthapi.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import java.util.List;

public record UpdateUserDTO(
	@Schema(description = "Nome", example = "Admin edited")
    @NotBlank(message = "O nome não pode estar vazio")
    String name,
	@Schema(description = "Lista de códigos de acesso (flags). Null = não altera; lista vazia = remove todas.")
    List<String> accessFlags,
	@Schema(description = "Role do usuário (ADMIN, USER, UNVERIFIED). Null = não altera. Apenas em contexto admin (flag USER_MANAGE).")
    String role,
    @Schema(description = "Idioma preferido do usuário (pt-BR, en-US). Null = não altera.", example = "pt-BR")
    String preferredLanguage
) {}