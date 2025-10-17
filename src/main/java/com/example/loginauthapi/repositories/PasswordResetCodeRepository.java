package com.example.loginauthapi.repositories;

import com.example.loginauthapi.domain.PasswordResetCode;
import com.example.loginauthapi.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetCodeRepository extends JpaRepository<PasswordResetCode, UUID> {
    
    Optional<PasswordResetCode> findByCodeAndUser(String code, User user);
    
    Optional<PasswordResetCode> findByCode(String code);
    
    @Modifying
    @Query("DELETE FROM PasswordResetCode prc WHERE prc.user = :user")
    void deleteByUser(@Param("user") User user);
    
    @Modifying
    @Query("DELETE FROM PasswordResetCode prc WHERE prc.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);
    
    @Query("SELECT COUNT(prc) FROM PasswordResetCode prc WHERE prc.user.id = :userId AND prc.createdAt >= :since")
    long countByUserAndCreatedAtAfter(@Param("userId") UUID userId, @Param("since") java.time.LocalDateTime since);
}
