// src/main/java/com/example/loginauthapi/dto/UserResponseDTO.java
package com.example.loginauthapi.dto;

public record UserResponseDTO(
    String id,
    String name,
    String email,
    String role
) {}