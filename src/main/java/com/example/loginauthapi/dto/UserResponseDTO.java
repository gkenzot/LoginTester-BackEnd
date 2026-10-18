// src/main/java/com/example/loginauthapi/dto/UserResponseDTO.java
package com.example.loginauthapi.dto;

import java.util.List;

public record UserResponseDTO(
    String id,
    String name,
    String email,
    String role,
    String preferredLanguage,
    String profilePhotoUrl,
    List<String> accessFlags
) {}