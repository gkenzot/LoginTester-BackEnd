package com.example.loginauthapi.controller;

import com.example.loginauthapi.dto.*;
import com.example.loginauthapi.service.UserService;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @Operation(summary = "Traz informações do usuário")
    @GetMapping("/me")
    public ResponseEntity<UserResponseDTO> getCurrentUser() {
        String email = getAuthenticatedUserEmail();
        return ResponseEntity.ok(userService.getCurrentUser(email));
    }

    @Operation(summary = "Atualiza informações do usuário")
    @PatchMapping("/me")
    public ResponseEntity<UserResponseDTO> updateUserInfo(@RequestBody @Valid UpdateUserDTO dto) {
        String email = getAuthenticatedUserEmail();
        UserResponseDTO updatedUser = userService.updateUserInfo(email, dto);
        return ResponseEntity.ok(updatedUser);
    }

    @Operation(summary = "Atualiza a senha com dupla verificação")
    @PatchMapping("/me/password")
    public ResponseEntity<Void> updatePassword(@RequestBody @Valid UpdatePasswordDTO dto) {
        String email = getAuthenticatedUserEmail();
        userService.updatePassword(email, dto);
        return ResponseEntity.noContent().build();
    }
    
    private String getAuthenticatedUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }
}