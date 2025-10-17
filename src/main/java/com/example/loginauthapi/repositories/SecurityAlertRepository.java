package com.example.loginauthapi.repositories;

import com.example.loginauthapi.domain.SecurityAlert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Repositório para alertas de segurança
 * 
 * Fornece métodos para consultar e gerenciar alertas de segurança
 */
@Repository
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, UUID> {

    /**
     * Busca alertas por status
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.status = :status ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findByStatusOrderByCreatedAtDesc(@Param("status") SecurityAlert.AlertStatus status);

    /**
     * Busca alertas por status com paginação
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.status = :status ORDER BY sa.createdAt DESC")
    Page<SecurityAlert> findByStatusOrderByCreatedAtDesc(@Param("status") SecurityAlert.AlertStatus status, Pageable pageable);

    /**
     * Busca alertas por severidade
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.severity = :severity ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findBySeverityOrderByCreatedAtDesc(@Param("severity") SecurityAlert.AlertSeverity severity);

    /**
     * Busca alertas por tipo
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.alertType = :alertType ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findByAlertTypeOrderByCreatedAtDesc(@Param("alertType") String alertType);

    /**
     * Busca alertas por usuário
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.userId = :userId ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findByUserIdOrderByCreatedAtDesc(@Param("userId") String userId);

    /**
     * Busca alertas por IP
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.ipAddress = :ipAddress ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findByIpAddressOrderByCreatedAtDesc(@Param("ipAddress") String ipAddress);

    /**
     * Busca alertas por período
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.createdAt BETWEEN :startDate AND :endDate ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findByCreatedAtBetweenOrderByCreatedAtDesc(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Busca alertas ativos por período
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.status = 'ACTIVE' AND sa.createdAt BETWEEN :startDate AND :endDate ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findActiveAlertsByPeriodOrderByCreatedAtDesc(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Busca alertas críticos ativos
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.severity = 'CRITICAL' AND sa.status = 'ACTIVE' ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findCriticalActiveAlertsOrderByCreatedAtDesc();

    /**
     * Busca alertas por múltiplos critérios
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE " +
           "(:status IS NULL OR sa.status = :status) AND " +
           "(:severity IS NULL OR sa.severity = :severity) AND " +
           "(:alertType IS NULL OR sa.alertType = :alertType) AND " +
           "(:userId IS NULL OR sa.userId = :userId) AND " +
           "(:ipAddress IS NULL OR sa.ipAddress = :ipAddress) AND " +
           "(:startDate IS NULL OR sa.createdAt >= :startDate) AND " +
           "(:endDate IS NULL OR sa.createdAt <= :endDate) " +
           "ORDER BY sa.createdAt DESC")
    Page<SecurityAlert> findAlertsByCriteria(
        @Param("status") SecurityAlert.AlertStatus status,
        @Param("severity") SecurityAlert.AlertSeverity severity,
        @Param("alertType") String alertType,
        @Param("userId") String userId,
        @Param("ipAddress") String ipAddress,
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate,
        Pageable pageable
    );

    /**
     * Conta alertas por status
     */
    @Query("SELECT sa.status, COUNT(sa) FROM SecurityAlert sa GROUP BY sa.status")
    List<Object[]> countAlertsByStatus();

    /**
     * Conta alertas por severidade
     */
    @Query("SELECT sa.severity, COUNT(sa) FROM SecurityAlert sa GROUP BY sa.severity")
    List<Object[]> countAlertsBySeverity();

    /**
     * Conta alertas por tipo
     */
    @Query("SELECT sa.alertType, COUNT(sa) FROM SecurityAlert sa GROUP BY sa.alertType")
    List<Object[]> countAlertsByType();

    /**
     * Conta alertas ativos por severidade
     */
    @Query("SELECT sa.severity, COUNT(sa) FROM SecurityAlert sa WHERE sa.status = 'ACTIVE' GROUP BY sa.severity")
    List<Object[]> countActiveAlertsBySeverity();

    /**
     * Busca alertas recentes (últimas 24 horas)
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.createdAt >= :since ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findRecentAlerts(@Param("since") LocalDateTime since);

    /**
     * Busca alertas não resolvidos por período
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.status IN ('ACTIVE', 'ESCALATED') AND sa.createdAt BETWEEN :startDate AND :endDate ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findUnresolvedAlertsByPeriodOrderByCreatedAtDesc(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Busca alertas por usuário e período
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.userId = :userId AND sa.createdAt BETWEEN :startDate AND :endDate ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findByUserIdAndCreatedAtBetweenOrderByCreatedAtDesc(
        @Param("userId") String userId,
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Busca alertas por IP e período
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.ipAddress = :ipAddress AND sa.createdAt BETWEEN :startDate AND :endDate ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findByIpAddressAndCreatedAtBetweenOrderByCreatedAtDesc(
        @Param("ipAddress") String ipAddress,
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Deleta alertas antigos (para limpeza de dados)
     */
    @Query("DELETE FROM SecurityAlert sa WHERE sa.createdAt < :cutoffDate")
    int deleteOldAlerts(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Busca alertas similares (mesmo tipo e IP)
     */
    @Query("SELECT sa FROM SecurityAlert sa WHERE sa.alertType = :alertType AND sa.ipAddress = :ipAddress AND sa.createdAt >= :since ORDER BY sa.createdAt DESC")
    List<SecurityAlert> findSimilarAlerts(
        @Param("alertType") String alertType, 
        @Param("ipAddress") String ipAddress, 
        @Param("since") LocalDateTime since
    );
}
