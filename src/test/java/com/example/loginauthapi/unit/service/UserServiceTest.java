package com.example.loginauthapi.unit.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.domain.UserRole;
import com.example.loginauthapi.dto.UpdatePasswordDTO;
import com.example.loginauthapi.dto.UpdateUserDTO;
import com.example.loginauthapi.dto.UserResponseDTO;
import com.example.loginauthapi.repositories.UserRepository;
import com.example.loginauthapi.service.UserServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImpl userService;

    private User testUser;
    private UpdateUserDTO updateUserDTO;
    private UpdatePasswordDTO updatePasswordDTO;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setEmail("test@mail.com");
        testUser.setName("Test User");
        testUser.setPassword("encodedPassword");
        testUser.setRole(UserRole.USER);

        updateUserDTO = new UpdateUserDTO("Updated Name");

        updatePasswordDTO = new UpdatePasswordDTO(
            "currentPassword",
            "newPassword123!",
            "newPassword123!"
        );
    }

    // Testes de Busca de Usuário (3 testes)

    @Test
    void getCurrentUser_WithValidEmail_ShouldReturnUserResponse() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));

        // When
        UserResponseDTO result = userService.getCurrentUser("test@mail.com");

        // Then
        assertThat(result).isNotNull();
        assertThat(result.id()).isEqualTo("user-123");
        assertThat(result.name()).isEqualTo("Test User");
        assertThat(result.email()).isEqualTo("test@mail.com");
        assertThat(result.role()).isEqualTo("USER");
    }

    @Test
    void getCurrentUser_WithNonExistentEmail_ShouldThrowNotFound() {
        // Given
        when(userRepository.findByEmail("nonexistent@mail.com")).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userService.getCurrentUser("nonexistent@mail.com"))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.NOT_FOUND)
            .hasMessageContaining("User not found");
    }

    @Test
    void getCurrentUser_WithNullEmail_ShouldThrowNotFound() {
        // Given
        when(userRepository.findByEmail(null)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userService.getCurrentUser(null))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.NOT_FOUND)
            .hasMessageContaining("User not found");
    }

    // Testes de Atualização de Informações (4 testes)

    @Test
    void updateUserInfo_WithValidData_ShouldUpdateAndReturnUser() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        UserResponseDTO result = userService.updateUserInfo("test@mail.com", updateUserDTO);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.name()).isEqualTo("Updated Name");
        verify(userRepository).save(testUser);
        assertThat(testUser.getName()).isEqualTo("Updated Name");
    }

    @Test
    void updateUserInfo_WithEmptyName_ShouldThrowBadRequest() {
        // Given
        UpdateUserDTO emptyNameDTO = new UpdateUserDTO("");

        // When & Then
        assertThatThrownBy(() -> userService.updateUserInfo("test@mail.com", emptyNameDTO))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST)
            .hasMessageContaining("Name cannot be empty");
    }

    @Test
    void updateUserInfo_WithNullName_ShouldThrowBadRequest() {
        // Given
        UpdateUserDTO nullNameDTO = new UpdateUserDTO(null);

        // When & Then
        assertThatThrownBy(() -> userService.updateUserInfo("test@mail.com", nullNameDTO))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST)
            .hasMessageContaining("Name cannot be empty");
    }

    @Test
    void updateUserInfo_WithWhitespaceOnlyName_ShouldThrowBadRequest() {
        // Given
        UpdateUserDTO whitespaceNameDTO = new UpdateUserDTO("   ");

        // When & Then
        assertThatThrownBy(() -> userService.updateUserInfo("test@mail.com", whitespaceNameDTO))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST)
            .hasMessageContaining("Name cannot be empty");
    }

    // Testes de Atualização de Senha (3 testes)

    @Test
    void updatePassword_WithValidData_ShouldUpdatePassword() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("currentPassword", "encodedPassword")).thenReturn(true);
        when(passwordEncoder.encode("newPassword123!")).thenReturn("newEncodedPassword");

        // When
        userService.updatePassword("test@mail.com", updatePasswordDTO);

        // Then
        verify(passwordEncoder).matches("currentPassword", "encodedPassword");
        verify(passwordEncoder).encode("newPassword123!");
        verify(userRepository).save(testUser);
        assertThat(testUser.getPassword()).isEqualTo("newEncodedPassword");
    }

    @Test
    void updatePassword_WithIncorrectCurrentPassword_ShouldThrowUnauthorized() {
        // Given
        when(userRepository.findByEmail("test@mail.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrongPassword", "encodedPassword")).thenReturn(false);

        UpdatePasswordDTO wrongCurrentPasswordDTO = new UpdatePasswordDTO(
            "wrongPassword",
            "newPassword123!",
            "newPassword123!"
        );

        // When & Then
        assertThatThrownBy(() -> userService.updatePassword("test@mail.com", wrongCurrentPasswordDTO))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.UNAUTHORIZED)
            .hasMessageContaining("Current password is incorrect");
    }

    @Test
    void updatePassword_WithPasswordMismatch_ShouldThrowBadRequest() {
        // Given
        UpdatePasswordDTO mismatchPasswordDTO = new UpdatePasswordDTO(
            "currentPassword",
            "newPassword123!",
            "differentPassword123!"
        );

        // When & Then
        assertThatThrownBy(() -> userService.updatePassword("test@mail.com", mismatchPasswordDTO))
            .isInstanceOf(ResponseStatusException.class)
            .hasFieldOrPropertyWithValue("status", HttpStatus.BAD_REQUEST)
            .hasMessageContaining("New password and confirmation do not match");
    }
}
