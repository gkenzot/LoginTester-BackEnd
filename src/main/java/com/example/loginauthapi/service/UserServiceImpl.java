package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.dto.*;
import com.example.loginauthapi.repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.*;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserResponseDTO getCurrentUser(String email) {
        User user = findUserByEmail(email);
        return mapToUserResponseDTO(user);
    }

    @Override
    public UserResponseDTO updateUserInfo(String email, UpdateUserDTO dto) {
        if (dto.name() == null || dto.name().trim().isEmpty()) {
            throw new ResponseStatusException(BAD_REQUEST, "Name cannot be empty");
        }
        
        User user = findUserByEmail(email);
        user.setName(dto.name().trim());
        User updatedUser = userRepository.save(user);
        return mapToUserResponseDTO(updatedUser);
    }

    @Override
    public void updatePassword(String email, UpdatePasswordDTO dto) {
        if (!dto.passwordsMatch()) {
            throw new ResponseStatusException(BAD_REQUEST, "New password and confirmation do not match");
        }
        
        User user = findUserByEmail(email);
        
        if (!passwordEncoder.matches(dto.currentPassword(), user.getPassword())) {
            throw new ResponseStatusException(UNAUTHORIZED, "Current password is incorrect");
        }
        
        user.setPassword(passwordEncoder.encode(dto.newPassword()));
        userRepository.save(user);
    }
    
    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "User not found"));
    }
    
    private UserResponseDTO mapToUserResponseDTO(User user) {
        return new UserResponseDTO(
            user.getId(),
            user.getName(),
            user.getEmail(),
            user.getRole().name()
        );
    }
}