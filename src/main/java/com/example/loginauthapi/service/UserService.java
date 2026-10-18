package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.UpdatePasswordDTO;
import com.example.loginauthapi.dto.UpdateUserDTO;
import com.example.loginauthapi.dto.UserResponseDTO;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

public interface UserService {
    /** Converte entidade User em DTO de resposta (uso em auth: login, refresh, register). */
    UserResponseDTO toUserResponseDTO(User user);

    UserResponseDTO getCurrentUser(String email);
    UserResponseDTO updateUserInfo(String email, UpdateUserDTO dto);
    void updatePassword(String email, UpdatePasswordDTO dto);
    UserResponseDTO uploadProfilePhoto(String email, MultipartFile file);
    UserResponseDTO removeProfilePhoto(String email);
    Resource getProfilePhoto(String email);
    String getProfilePhotoContentType(String email);
    /** Retorna foto + contentType em uma única consulta ao banco. */
    ProfilePhotoResult getProfilePhotoResource(String email);
    
    // Admin methods
    List<UserResponseDTO> getAllUsers();
    UserResponseDTO getUserById(UUID userId);
    UserResponseDTO updateUserById(UUID userId, UpdateUserDTO dto);
    void deleteUserById(UUID userId);
}