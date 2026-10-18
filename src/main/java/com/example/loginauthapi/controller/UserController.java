package com.example.loginauthapi.controller;

import com.example.loginauthapi.dto.*;
import com.example.loginauthapi.service.UserService;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;

import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.Duration;

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

    @Operation(summary = "Faz upload da foto de perfil do usuário")
    @PostMapping(value = "/me/photo", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<UserResponseDTO> uploadProfilePhoto(@RequestParam("file") MultipartFile file) {
        String email = getAuthenticatedUserEmail();
        UserResponseDTO updatedUser = userService.uploadProfilePhoto(email, file);
        return ResponseEntity.ok(updatedUser);
    }

    @Operation(summary = "Obtém a foto de perfil do usuário autenticado")
    @GetMapping("/me/photo")
    public ResponseEntity<Resource> getCurrentUserProfilePhoto() {
        String email = getAuthenticatedUserEmail();
        var photoResult = userService.getProfilePhotoResource(email);
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(photoResult.contentType()))
            .header(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().cachePrivate().mustRevalidate().getHeaderValue())
            .cacheControl(CacheControl.maxAge(Duration.ZERO))
            .body(photoResult.resource());
    }

    @Operation(summary = "Remove a foto de perfil do usuário autenticado")
    @DeleteMapping("/me/photo")
    public ResponseEntity<UserResponseDTO> removeCurrentUserProfilePhoto() {
        String email = getAuthenticatedUserEmail();
        UserResponseDTO updatedUser = userService.removeProfilePhoto(email);
        return ResponseEntity.ok(updatedUser);
    }
    
    private String getAuthenticatedUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName();
    }
}