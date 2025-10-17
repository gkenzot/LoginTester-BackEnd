package com.example.loginauthapi.repositories;

import com.example.loginauthapi.domain.AuditEvent;
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
 * Repositório para eventos de auditoria
 * 
 * Fornece métodos para consultar e filtrar eventos de auditoria
 */
@Repository
public interface AuditRepository extends JpaRepository<AuditEvent, UUID> {

    /**
     * Busca eventos de auditoria por usuário
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.userId = :userId ORDER BY ae.timestamp DESC")
    List<AuditEvent> findByUserIdOrderByTimestampDesc(@Param("userId") String userId);

    /**
     * Busca eventos de auditoria por usuário com paginação
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.userId = :userId ORDER BY ae.timestamp DESC")
    Page<AuditEvent> findByUserIdOrderByTimestampDesc(@Param("userId") String userId, Pageable pageable);

    /**
     * Busca eventos de auditoria por tipo de evento
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.eventType = :eventType ORDER BY ae.timestamp DESC")
    List<AuditEvent> findByEventTypeOrderByTimestampDesc(@Param("eventType") String eventType);

    /**
     * Busca eventos de auditoria por resultado
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.result = :result ORDER BY ae.timestamp DESC")
    List<AuditEvent> findByResultOrderByTimestampDesc(@Param("result") AuditEvent.AuditResult result);

    /**
     * Busca eventos de auditoria por IP
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.ipAddress = :ipAddress ORDER BY ae.timestamp DESC")
    List<AuditEvent> findByIpAddressOrderByTimestampDesc(@Param("ipAddress") String ipAddress);

    /**
     * Busca eventos de auditoria por período
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.timestamp BETWEEN :startDate AND :endDate ORDER BY ae.timestamp DESC")
    List<AuditEvent> findByTimestampBetweenOrderByTimestampDesc(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Busca eventos de auditoria por usuário e período
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.userId = :userId AND ae.timestamp BETWEEN :startDate AND :endDate ORDER BY ae.timestamp DESC")
    List<AuditEvent> findByUserIdAndTimestampBetweenOrderByTimestampDesc(
        @Param("userId") String userId,
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Busca eventos suspeitos (resultado SUSPICIOUS)
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.result = 'SUSPICIOUS' ORDER BY ae.timestamp DESC")
    List<AuditEvent> findSuspiciousEventsOrderByTimestampDesc();

    /**
     * Busca eventos suspeitos por período
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.result = 'SUSPICIOUS' AND ae.timestamp BETWEEN :startDate AND :endDate ORDER BY ae.timestamp DESC")
    List<AuditEvent> findSuspiciousEventsByPeriodOrderByTimestampDesc(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Busca eventos de login (sucesso e falha)
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.eventType IN ('LOGIN_SUCCESS', 'LOGIN_FAILURE') ORDER BY ae.timestamp DESC")
    List<AuditEvent> findLoginEventsOrderByTimestampDesc();

    /**
     * Busca eventos de login por período
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.eventType IN ('LOGIN_SUCCESS', 'LOGIN_FAILURE') AND ae.timestamp BETWEEN :startDate AND :endDate ORDER BY ae.timestamp DESC")
    List<AuditEvent> findLoginEventsByPeriodOrderByTimestampDesc(
        @Param("startDate") LocalDateTime startDate, 
        @Param("endDate") LocalDateTime endDate
    );

    /**
     * Conta eventos por tipo
     */
    @Query("SELECT ae.eventType, COUNT(ae) FROM AuditEvent ae GROUP BY ae.eventType")
    List<Object[]> countEventsByType();

    /**
     * Conta eventos por resultado
     */
    @Query("SELECT ae.result, COUNT(ae) FROM AuditEvent ae GROUP BY ae.result")
    List<Object[]> countEventsByResult();

    /**
     * Conta eventos por IP (para detectar atividades suspeitas)
     */
    @Query("SELECT ae.ipAddress, COUNT(ae) FROM AuditEvent ae WHERE ae.ipAddress IS NOT NULL GROUP BY ae.ipAddress ORDER BY COUNT(ae) DESC")
    List<Object[]> countEventsByIpAddress();

    /**
     * Busca eventos recentes (últimas 24 horas)
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.timestamp >= :since ORDER BY ae.timestamp DESC")
    List<AuditEvent> findRecentEvents(@Param("since") LocalDateTime since);

    /**
     * Busca eventos recentes por usuário
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE ae.userId = :userId AND ae.timestamp >= :since ORDER BY ae.timestamp DESC")
    List<AuditEvent> findRecentEventsByUser(@Param("userId") String userId, @Param("since") LocalDateTime since);

    /**
     * Busca eventos por múltiplos critérios com paginação
     */
    @Query("SELECT ae FROM AuditEvent ae WHERE " +
           "(:userId IS NULL OR ae.userId = :userId) AND " +
           "(:eventType IS NULL OR ae.eventType = :eventType) AND " +
           "(:result IS NULL OR ae.result = :result) AND " +
           "(:ipAddress IS NULL OR ae.ipAddress = :ipAddress) AND " +
           "(:startDate IS NULL OR ae.timestamp >= :startDate) AND " +
           "(:endDate IS NULL OR ae.timestamp <= :endDate) " +
           "ORDER BY ae.timestamp DESC")
    Page<AuditEvent> findEventsByCriteria(
        @Param("userId") String userId,
        @Param("eventType") String eventType,
        @Param("result") AuditEvent.AuditResult result,
        @Param("ipAddress") String ipAddress,
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate,
        Pageable pageable
    );

    /**
     * Deleta eventos antigos (para limpeza de dados)
     */
    @Query("DELETE FROM AuditEvent ae WHERE ae.timestamp < :cutoffDate")
    int deleteOldEvents(@Param("cutoffDate") LocalDateTime cutoffDate);
}
