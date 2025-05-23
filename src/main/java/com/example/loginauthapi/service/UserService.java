// src/main/java/com/example/loginauthapi/service/UserService.java
package com.example.loginauthapi.service;

import com.example.loginauthapi.dto.UpdatePasswordDTO;
import com.example.loginauthapi.dto.UpdateUserDTO;
import com.example.loginauthapi.dto.UserResponseDTO;

public interface UserService {
    UserResponseDTO getCurrentUser(String email);
    UserResponseDTO updateUserInfo(String email, UpdateUserDTO dto);
    void updatePassword(String email, UpdatePasswordDTO dto);
}