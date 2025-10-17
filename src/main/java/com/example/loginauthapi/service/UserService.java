package com.example.loginauthapi.service;

import com.example.loginauthapi.dto.UpdatePasswordDTO;
import com.example.loginauthapi.dto.UpdateUserDTO;
import com.example.loginauthapi.dto.UserResponseDTO;

import java.util.List;
import java.util.UUID;

public interface UserService {
    UserResponseDTO getCurrentUser(String email);
    UserResponseDTO updateUserInfo(String email, UpdateUserDTO dto);
    void updatePassword(String email, UpdatePasswordDTO dto);
    
    // Admin methods
    List<UserResponseDTO> getAllUsers();
    UserResponseDTO getUserById(UUID userId);
    UserResponseDTO updateUserById(UUID userId, UpdateUserDTO dto);
    void deleteUserById(UUID userId);
}