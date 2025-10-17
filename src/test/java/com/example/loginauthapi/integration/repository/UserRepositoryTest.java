package com.example.loginauthapi.integration.repository;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.domain.UserRole;
import com.example.loginauthapi.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        entityManager.clear();
        entityManager.flush();
    }

    @Test
    @DisplayName("Should persist a user successfully")
    void save_WithValidUser_ShouldPersistUser() {
        // Given
        User user = new User(null, "Test User", "test@example.com", "password123", UserRole.USER);

        // When
        User savedUser = userRepository.save(user);

        // Then
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getId()).isNotNull();
        assertThat(savedUser.getName()).isEqualTo("Test User");
        assertThat(savedUser.getEmail()).isEqualTo("test@example.com");
        assertThat(savedUser.getPassword()).isEqualTo("password123");
        assertThat(savedUser.getRole()).isEqualTo(UserRole.USER);
    }

    @Test
    @DisplayName("Should find user by ID successfully")
    void findById_WithExistingId_ShouldReturnUser() {
        // Given
        User user = new User(null, "Test User", "test@example.com", "password123", UserRole.USER);
        entityManager.persistAndFlush(user);

        // When
        Optional<User> foundUser = userRepository.findById(user.getId());

        // Then
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getId()).isEqualTo(user.getId());
    }

    @Test
    @DisplayName("Should return empty when user not found by ID")
    void findById_WithNonExistingId_ShouldReturnEmpty() {
        // When
        Optional<User> foundUser = userRepository.findById(UUID.randomUUID());

        // Then
        assertThat(foundUser).isEmpty();
    }

    @Test
    @DisplayName("Should find user by email successfully")
    void findByEmail_WithExistingEmail_ShouldReturnUser() {
        // Given
        User testUser = new User(null, "Test User", "test@example.com", "password123", UserRole.USER);
        userRepository.save(testUser);

        // When
        Optional<User> foundUser = userRepository.findByEmail("test@example.com");

        // Then
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    @DisplayName("Should return empty when user not found by email")
    void findByEmail_WithNonExistingEmail_ShouldReturnEmpty() {
        // When
        Optional<User> foundUser = userRepository.findByEmail("nonexistent@example.com");

        // Then
        assertThat(foundUser).isEmpty();
    }

    @Test
    @DisplayName("Should update an existing user successfully")
    void update_WithExistingUser_ShouldUpdateUser() {
        // Given
        User user = new User(null, "Original Name", "update@example.com", "oldpass", UserRole.USER);
        entityManager.persistAndFlush(user);
        entityManager.clear(); // Detach the entity

        User userToUpdate = userRepository.findById(user.getId()).get();
        userToUpdate.setName("Updated Name");
        userToUpdate.setPassword("newpass");

        // When
        User updatedUser = userRepository.save(userToUpdate);

        // Then
        assertThat(updatedUser).isNotNull();
        assertThat(updatedUser.getName()).isEqualTo("Updated Name");
        assertThat(updatedUser.getPassword()).isEqualTo("newpass");
    }

    @Test
    @DisplayName("Should delete a user successfully")
    void delete_WithExistingUser_ShouldRemoveUser() {
        // Given
        User testUser = new User(null, "Test User", "test@example.com", "password123", UserRole.USER);
        User savedUser = userRepository.save(testUser);

        // When
        userRepository.deleteById(savedUser.getId());

        // Then
        Optional<User> deletedUser = userRepository.findById(savedUser.getId());
        assertThat(deletedUser).isEmpty();
    }

    @Test
    @DisplayName("Should find all users successfully")
    void findAll_WithMultipleUsers_ShouldReturnAllUsers() {
        // Given
        User testUser1 = new User(null, "Test User 1", "test1@example.com", "password123", UserRole.USER);
        User testUser2 = new User(null, "Test User 2", "test2@example.com", "password123", UserRole.ADMIN);
        userRepository.save(testUser1);
        userRepository.save(testUser2);

        // When
        List<User> users = userRepository.findAll();

        // Then
        assertThat(users).hasSize(2);
    }

    @Test
    @DisplayName("Should return empty list when no users exist")
    void findAll_WithNoUsers_ShouldReturnEmptyList() {
        // When
        List<User> users = userRepository.findAll();

        // Then
        assertThat(users).isEmpty();
    }

    @Test
    @DisplayName("Should not save user with duplicate email")
    void save_WithDuplicateEmail_ShouldThrowException() {
        // Given
        User testUser1 = new User(null, "Test User 1", "test@example.com", "password123", UserRole.USER);
        User testUser2 = new User(null, "Test User 2", "test@example.com", "anotherpass", UserRole.USER);
        
        // Save first user
        userRepository.save(testUser1);
        
        // When & Then - try to save second user with same email
        assertThatThrownBy(() -> {
            userRepository.save(testUser2);
            entityManager.flush(); // Force the constraint check
        })
        .isInstanceOf(org.hibernate.exception.ConstraintViolationException.class);
    }
}