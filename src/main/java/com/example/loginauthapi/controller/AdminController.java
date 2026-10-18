package com.example.loginauthapi.controller;

import com.example.loginauthapi.domain.AccessFlag;
import com.example.loginauthapi.dto.UpdateUserDTO;
import com.example.loginauthapi.dto.UserResponseDTO;
import com.example.loginauthapi.service.UserService;
import com.example.loginauthapi.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Administração", description = "Endpoints para administração de usuários")
public class AdminController {

    private final UserService userService;
    private final AuthService authService;

    @GetMapping("/users")
    @Operation(summary = "Listar todos os usuários", description = "Retorna lista de todos os usuários (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Lista de usuários retornada com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN")
    })
    public ResponseEntity<List<UserResponseDTO>> getAllUsers(
            @CookieValue(name = "jwt", required = false) String token,
            HttpServletRequest request) {
        
        log.info("Admin request to list all users");
        
        // Acesso: ADMIN ou USER com flag 001 (administrar usuários e flags)
        authService.validateAccessByFlag(token, AccessFlag.MANAGE_USERS_AND_FLAGS);
        
        List<UserResponseDTO> users = userService.getAllUsers();
        log.info("Retrieved {} users for admin", users.size());
        
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{userId}")
    @Operation(summary = "Obter usuário por ID", description = "Retorna dados de um usuário específico (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Usuário encontrado"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "404", description = "Usuário não encontrado")
    })
    public ResponseEntity<UserResponseDTO> getUserById(
            @PathVariable UUID userId,
            @CookieValue(name = "jwt", required = false) String token,
            HttpServletRequest request) {
        
        log.info("Admin request to get user by ID: {}", userId);
        
        authService.validateAccessByFlag(token, AccessFlag.MANAGE_USERS_AND_FLAGS);
        
        UserResponseDTO user = userService.getUserById(userId);
        log.info("Retrieved user: {}", user.email());
        
        return ResponseEntity.ok(user);
    }

    @PutMapping("/users/{userId}")
    @Operation(summary = "Atualizar usuário", description = "Atualiza dados de um usuário específico (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Usuário atualizado com sucesso"),
        @ApiResponse(responseCode = "400", description = "Dados inválidos"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "404", description = "Usuário não encontrado")
    })
    public ResponseEntity<UserResponseDTO> updateUser(
            @PathVariable UUID userId,
            @RequestBody @Valid UpdateUserDTO dto,
            @CookieValue(name = "jwt", required = false) String token,
            HttpServletRequest request) {
        
        log.info("Admin request to update user: {}", userId);
        
        authService.validateAccessByFlag(token, AccessFlag.MANAGE_USERS_AND_FLAGS);
        
        UserResponseDTO updatedUser = userService.updateUserById(userId, dto);
        log.info("Updated user: {}", updatedUser.email());
        
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/users/{userId}")
    @Operation(summary = "Excluir usuário", description = "Exclui um usuário específico (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Usuário excluído com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "404", description = "Usuário não encontrado")
    })
    public ResponseEntity<Void> deleteUser(
            @PathVariable UUID userId,
            @CookieValue(name = "jwt", required = false) String token,
            HttpServletRequest request) {
        
        log.info("Admin request to delete user: {}", userId);
        
        authService.validateAccessByFlag(token, AccessFlag.MANAGE_USERS_AND_FLAGS);
        
        userService.deleteUserById(userId);
        log.info("Deleted user: {}", userId);
        
        return ResponseEntity.noContent().build();
    }

}
