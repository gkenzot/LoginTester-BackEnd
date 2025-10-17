// src/main/java/com/example/loginauthapi/repositories/UserRepository.java
package com.example.loginauthapi.repositories;

import com.example.loginauthapi.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
}