package com.example.loginauthapi.repositories;

import com.example.loginauthapi.domain.EmailVerificationCode;
import com.example.loginauthapi.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmailVerificationCodeRepository extends JpaRepository<EmailVerificationCode, UUID> {
    Optional<EmailVerificationCode> findByUserAndCodeAndUsedFalseAndExpiresAtAfter(User user, String code, LocalDateTime now);
    Optional<EmailVerificationCode> findByCodeAndUsedFalseAndExpiresAtAfter(String code, LocalDateTime now);
    
    @Query("SELECT COUNT(evc) FROM EmailVerificationCode evc WHERE evc.user.id = :userId AND evc.createdAt >= :since")
    long countByUserAndCreatedAtAfter(@Param("userId") UUID userId, @Param("since") LocalDateTime since);
    
    void deleteAllByUser(User user);
}
