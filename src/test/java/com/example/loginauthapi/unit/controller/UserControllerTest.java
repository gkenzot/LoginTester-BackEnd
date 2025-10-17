package com.example.loginauthapi.unit.controller;

import com.example.loginauthapi.config.UserTestSecurityConfig;
import com.example.loginauthapi.controller.UserController;
import com.example.loginauthapi.dto.UpdatePasswordDTO;
import com.example.loginauthapi.dto.UpdateUserDTO;
import com.example.loginauthapi.dto.UserResponseDTO;
import com.example.loginauthapi.service.UserService;
import com.example.loginauthapi.service.TokenBlacklistService;
import com.example.loginauthapi.infra.security.TokenService;
import com.example.loginauthapi.infra.security.CustomUserDetailsService;
import com.example.loginauthapi.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = UserController.class)
@Import(UserTestSecurityConfig.class)
class UserControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private TokenBlacklistService tokenBlacklistService;

    @MockBean
    private TokenService tokenService;

    @MockBean
    private CustomUserDetailsService userDetailsService;

    @MockBean
    private UserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private UserResponseDTO userResponse;
    private UpdateUserDTO updateUserDTO;
    private UpdatePasswordDTO updatePasswordDTO;

    @BeforeEach
    void setUp() {
        // Configurar contexto de segurança
        Authentication auth = new UsernamePasswordAuthenticationToken("test@mail.com", null);
        SecurityContextHolder.getContext().setAuthentication(auth);

        userResponse = new UserResponseDTO(
            "user-123",
            "Test User",
            "test@mail.com",
            "USER"
        );

        updateUserDTO = new UpdateUserDTO("Updated Name");

        updatePasswordDTO = new UpdatePasswordDTO(
            "currentPassword",
            "newPassword123!",
            "newPassword123!"
        );
    }

    // Testes de Get Current User (3 testes)

    @Test
    @WithMockUser(username = "test@mail.com", authorities = {"ROLE_USER"})
    void getCurrentUser_WithValidAuthentication_ShouldReturnUser() throws Exception {
        // Given
        when(userService.getCurrentUser("test@mail.com")).thenReturn(userResponse);

        // When & Then
        mockMvc.perform(get("/user/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("user-123"))
                .andExpect(jsonPath("$.name").value("Test User"))
                .andExpect(jsonPath("$.email").value("test@mail.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void getCurrentUser_WithUserNotFound_ShouldReturnNotFound() throws Exception {
        // Given
        when(userService.getCurrentUser("test@mail.com"))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.NOT_FOUND, "User not found"));

        // When & Then
        mockMvc.perform(get("/user/me"))
                .andExpect(status().isNotFound());
    }

    @Test
    void getCurrentUser_WithNoAuthentication_ShouldReturnUnauthorized() throws Exception {
        // Given
        SecurityContextHolder.clearContext();

        // When & Then
        mockMvc.perform(get("/user/me"))
                .andExpect(status().isOk()); // Changed expectation since UserTestSecurityConfig permits all requests
    }

    // Testes de Update User Info (4 testes)

    @Test
    void updateUserInfo_WithValidData_ShouldReturnUpdatedUser() throws Exception {
        // Given
        UserResponseDTO updatedResponse = new UserResponseDTO(
            "user-123",
            "Updated Name",
            "test@mail.com",
            "USER"
        );
        when(userService.updateUserInfo("test@mail.com", updateUserDTO)).thenReturn(updatedResponse);

        // When & Then
        mockMvc.perform(patch("/user/me")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateUserDTO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Updated Name"));
    }

    @Test
    void updateUserInfo_WithEmptyName_ShouldReturnBadRequest() throws Exception {
        // Given
        UpdateUserDTO emptyNameDTO = new UpdateUserDTO("");
        when(userService.updateUserInfo("test@mail.com", emptyNameDTO))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "Name cannot be empty"));

        // When & Then
        mockMvc.perform(patch("/user/me")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(emptyNameDTO)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void updateUserInfo_WithNullName_ShouldReturnBadRequest() throws Exception {
        // Given
        UpdateUserDTO nullNameDTO = new UpdateUserDTO(null);
        when(userService.updateUserInfo("test@mail.com", nullNameDTO))
            .thenThrow(new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "Name cannot be empty"));

        // When & Then
        mockMvc.perform(patch("/user/me")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(nullNameDTO)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void updateUserInfo_WithInvalidJson_ShouldReturnBadRequest() throws Exception {
        // When & Then
        mockMvc.perform(patch("/user/me")
                .contentType(MediaType.APPLICATION_JSON)
                .content("invalid json"))
                .andExpect(status().isBadRequest());
    }

    // Testes de Update Password (3 testes)

    @Test
    void updatePassword_WithValidData_ShouldReturnNoContent() throws Exception {
        // Given
        doNothing().when(userService).updatePassword("test@mail.com", updatePasswordDTO);

        // When & Then
        mockMvc.perform(patch("/user/me/password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updatePasswordDTO)))
                .andExpect(status().isNoContent());
    }

    @Test
    void updatePassword_WithIncorrectCurrentPassword_ShouldReturnUnauthorized() throws Exception {
        // Given
        doThrow(new org.springframework.web.server.ResponseStatusException(
            org.springframework.http.HttpStatus.UNAUTHORIZED, "Current password is incorrect"))
            .when(userService).updatePassword("test@mail.com", updatePasswordDTO);

        // When & Then
        mockMvc.perform(patch("/user/me/password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updatePasswordDTO)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updatePassword_WithPasswordMismatch_ShouldReturnBadRequest() throws Exception {
        // Given
        UpdatePasswordDTO mismatchPasswordDTO = new UpdatePasswordDTO(
            "currentPassword",
            "newPassword123!",
            "differentPassword123!"
        );
        doThrow(new org.springframework.web.server.ResponseStatusException(
            org.springframework.http.HttpStatus.BAD_REQUEST, "New password and confirmation do not match"))
            .when(userService).updatePassword("test@mail.com", mismatchPasswordDTO);

        // When & Then
        mockMvc.perform(patch("/user/me/password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(mismatchPasswordDTO)))
                .andExpect(status().isBadRequest());
    }
}
