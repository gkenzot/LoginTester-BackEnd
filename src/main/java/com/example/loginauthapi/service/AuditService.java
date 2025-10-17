package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.AuditEvent;
import com.example.loginauthapi.repositories.AuditRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Serviço de auditoria
 * 
 * Gerencia logs de auditoria para todas as operações críticas do sistema
 */
@Service
@Transactional
@RequiredArgsConstructor
public class AuditService {

    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);

    private final AuditRepository auditRepository;

    /**
     * Registra evento de auditoria de forma assíncrona
     */
    @Async
    public CompletableFuture<Void> logEventAsync(String userId, String eventType, String eventDescription,
                                               String ipAddress, String userAgent, AuditEvent.AuditResult result,
                                               Map<String, Object> metadata) {
        try {
            AuditEvent auditEvent = new AuditEvent(userId, eventType, eventDescription, ipAddress, userAgent, result);
            auditEvent.setMetadata(metadata);
            auditEvent.setTimestamp(LocalDateTime.now());
            
            auditRepository.save(auditEvent);
            
            logger.debug("Audit event logged: {} - {} - {}", eventType, userId, result);
            
        } catch (Exception e) {
            logger.error("Error logging audit event: {}", e.getMessage(), e);
        }
        
        return CompletableFuture.completedFuture(null);
    }

    /**
     * Registra evento de auditoria de forma síncrona
     */
    public void logEvent(String userId, String eventType, String eventDescription,
                        String ipAddress, String userAgent, AuditEvent.AuditResult result,
                        Map<String, Object> metadata) {
        try {
            AuditEvent auditEvent = new AuditEvent(userId, eventType, eventDescription, ipAddress, userAgent, result);
            auditEvent.setMetadata(metadata);
            auditEvent.setTimestamp(LocalDateTime.now());
            
            auditRepository.save(auditEvent);
            
            logger.debug("Audit event logged: {} - {} - {}", eventType, userId, result);
            
        } catch (Exception e) {
            logger.error("Error logging audit event: {}", e.getMessage(), e);
        }
    }

    /**
     * Registra tentativa de login
     */
    public void logLoginAttempt(String email, String ipAddress, String userAgent, boolean success) {
        String eventType = success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE";
        AuditEvent.AuditResult result = success ? AuditEvent.AuditResult.SUCCESS : AuditEvent.AuditResult.FAILURE;
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("email", email);
        metadata.put("success", success);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(email, eventType, 
            success ? "Login realizado com sucesso" : "Tentativa de login falhada",
            ipAddress, userAgent, result, metadata);
    }

    /**
     * Registra logout
     */
    public void logLogout(String userId, String ipAddress, String userAgent) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(userId, "LOGOUT", "Usuário fez logout",
            ipAddress, userAgent, AuditEvent.AuditResult.SUCCESS, metadata);
    }

    /**
     * Registra alteração de senha
     */
    public void logPasswordChange(String userId, String ipAddress, String userAgent) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(userId, "PASSWORD_CHANGE", "Senha alterada",
            ipAddress, userAgent, AuditEvent.AuditResult.SUCCESS, metadata);
    }

    /**
     * Registra atividade suspeita
     */
    public void logSuspiciousActivity(String userId, String activity, String ipAddress, String userAgent, Map<String, Object> details) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("activity", activity);
        metadata.put("details", details);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(userId, "SUSPICIOUS_ACTIVITY", "Atividade suspeita detectada: " + activity,
            ipAddress, userAgent, AuditEvent.AuditResult.SUSPICIOUS, metadata);
    }

    /**
     * Registra blacklist de token
     */
    public void logTokenBlacklist(String userId, String token, String reason, String ipAddress) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("token", token.substring(0, Math.min(20, token.length())) + "...");
        metadata.put("reason", reason);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(userId, "TOKEN_BLACKLIST", "Token adicionado à blacklist: " + reason,
            ipAddress, null, AuditEvent.AuditResult.SUCCESS, metadata);
    }

    /**
     * Registra tentativa de acesso negado
     */
    public void logAccessDenied(String userId, String resource, String ipAddress, String userAgent, String reason) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("resource", resource);
        metadata.put("reason", reason);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(userId, "ACCESS_DENIED", "Acesso negado: " + reason,
            ipAddress, userAgent, AuditEvent.AuditResult.BLOCKED, metadata);
    }

    /**
     * Registra refresh de token
     */
    public void logTokenRefresh(String userId, String ipAddress, String userAgent, boolean success) {
        String eventType = success ? "TOKEN_REFRESH_SUCCESS" : "TOKEN_REFRESH_FAILURE";
        AuditEvent.AuditResult result = success ? AuditEvent.AuditResult.SUCCESS : AuditEvent.AuditResult.FAILURE;
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("success", success);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(userId, eventType, 
            success ? "Token renovado com sucesso" : "Falha na renovação do token",
            ipAddress, userAgent, result, metadata);
    }

    /**
     * Registra registro de usuário
     */
    public void logUserRegistration(String email, String ipAddress, String userAgent, boolean success) {
        String eventType = success ? "USER_REGISTRATION_SUCCESS" : "USER_REGISTRATION_FAILURE";
        AuditEvent.AuditResult result = success ? AuditEvent.AuditResult.SUCCESS : AuditEvent.AuditResult.FAILURE;
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("email", email);
        metadata.put("success", success);
        metadata.put("timestamp", LocalDateTime.now());
        
        logEventAsync(email, eventType, 
            success ? "Usuário registrado com sucesso" : "Falha no registro de usuário",
            ipAddress, userAgent, result, metadata);
    }

    /**
     * Busca eventos de auditoria por usuário
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getAuditLogsByUser(String userId) {
        return auditRepository.findByUserIdOrderByTimestampDesc(userId);
    }

    /**
     * Busca eventos de auditoria por usuário com paginação
     */
    @Transactional(readOnly = true)
    public Page<AuditEvent> getAuditLogsByUser(String userId, Pageable pageable) {
        return auditRepository.findByUserIdOrderByTimestampDesc(userId, pageable);
    }

    /**
     * Busca eventos de auditoria por período
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getAuditLogsByPeriod(LocalDateTime startDate, LocalDateTime endDate) {
        return auditRepository.findByTimestampBetweenOrderByTimestampDesc(startDate, endDate);
    }

    /**
     * Busca eventos suspeitos
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getSuspiciousEvents() {
        return auditRepository.findSuspiciousEventsOrderByTimestampDesc();
    }

    /**
     * Busca eventos suspeitos por período
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getSuspiciousEventsByPeriod(LocalDateTime startDate, LocalDateTime endDate) {
        return auditRepository.findSuspiciousEventsByPeriodOrderByTimestampDesc(startDate, endDate);
    }

    /**
     * Busca eventos de login
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getLoginEvents() {
        return auditRepository.findLoginEventsOrderByTimestampDesc();
    }

    /**
     * Busca eventos de login por período
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getLoginEventsByPeriod(LocalDateTime startDate, LocalDateTime endDate) {
        return auditRepository.findLoginEventsByPeriodOrderByTimestampDesc(startDate, endDate);
    }

    /**
     * Busca eventos recentes (últimas 24 horas)
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getRecentEvents() {
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        return auditRepository.findRecentEvents(since);
    }

    /**
     * Busca eventos recentes por usuário
     */
    @Transactional(readOnly = true)
    public List<AuditEvent> getRecentEventsByUser(String userId) {
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        return auditRepository.findRecentEventsByUser(userId, since);
    }

    /**
     * Busca eventos por múltiplos critérios
     */
    @Transactional(readOnly = true)
    public Page<AuditEvent> getEventsByCriteria(String userId, String eventType, AuditEvent.AuditResult result,
                                                String ipAddress, LocalDateTime startDate, LocalDateTime endDate,
                                                Pageable pageable) {
        return auditRepository.findEventsByCriteria(userId, eventType, result, ipAddress, startDate, endDate, pageable);
    }

    /**
     * Obtém estatísticas de eventos
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getAuditStatistics() {
        List<Object[]> eventsByType = auditRepository.countEventsByType();
        List<Object[]> eventsByResult = auditRepository.countEventsByResult();
        List<Object[]> eventsByIp = auditRepository.countEventsByIpAddress();
        
        Map<String, Object> statistics = new HashMap<>();
        statistics.put("eventsByType", eventsByType);
        statistics.put("eventsByResult", eventsByResult);
        statistics.put("eventsByIp", eventsByIp);
        statistics.put("totalEvents", auditRepository.count());
        statistics.put("timestamp", LocalDateTime.now());
        
        return statistics;
    }

    /**
     * Limpa eventos antigos (para manutenção)
     */
    public int cleanupOldEvents(int daysToKeep) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysToKeep);
        int deletedCount = auditRepository.deleteOldEvents(cutoffDate);
        logger.info("Cleaned up {} old audit events older than {} days", deletedCount, daysToKeep);
        return deletedCount;
    }
}
