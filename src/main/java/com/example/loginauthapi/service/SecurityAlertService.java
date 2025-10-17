package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.SecurityAlert;
import com.example.loginauthapi.repositories.SecurityAlertRepository;
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
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Serviço de alertas de segurança
 * 
 * Gerencia alertas de segurança e suas regras de detecção
 */
@Service
@Transactional
@RequiredArgsConstructor
public class SecurityAlertService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAlertService.class);

    private final SecurityAlertRepository securityAlertRepository;
    private final AuditService auditService;

    /**
     * Cria um novo alerta de segurança
     */
    @Async
    public CompletableFuture<Void> createAlertAsync(String alertType, SecurityAlert.AlertSeverity severity,
                                                   String description, String userId, String ipAddress,
                                                   Map<String, Object> metadata) {
        try {
            SecurityAlert alert = new SecurityAlert(alertType, severity, description, userId, ipAddress, metadata);
            securityAlertRepository.save(alert);
            
            logger.info("Security alert created: {} - {} - {}", alertType, severity, description);
            
            // Log de auditoria
            Map<String, Object> auditMetadata = new HashMap<>();
            auditMetadata.put("alertId", alert.getId().toString());
            auditMetadata.put("alertType", alertType);
            
            auditService.logEvent(userId, "SECURITY_ALERT_CREATED", 
                "Alerta de segurança criado: " + description, ipAddress, null, 
                SecurityAlert.AlertSeverity.CRITICAL.equals(severity) ? 
                    com.example.loginauthapi.domain.AuditEvent.AuditResult.SUSPICIOUS : 
                    com.example.loginauthapi.domain.AuditEvent.AuditResult.SUCCESS, 
                auditMetadata);
            
        } catch (Exception e) {
            logger.error("Error creating security alert: {}", e.getMessage(), e);
        }
        
        return CompletableFuture.completedFuture(null);
    }

    /**
     * Cria um novo alerta de segurança de forma síncrona
     */
    public SecurityAlert createAlert(String alertType, SecurityAlert.AlertSeverity severity,
                                   String description, String userId, String ipAddress,
                                   Map<String, Object> metadata) {
        try {
            SecurityAlert alert = new SecurityAlert(alertType, severity, description, userId, ipAddress, metadata);
            SecurityAlert savedAlert = securityAlertRepository.save(alert);
            
            logger.info("Security alert created: {} - {} - {}", alertType, severity, description);
            
            return savedAlert;
            
        } catch (Exception e) {
            logger.error("Error creating security alert: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create security alert", e);
        }
    }

    /**
     * Verifica e cria alerta para múltiplas tentativas de login falhadas
     */
    public void checkMultipleFailedLogins(String ipAddress, int attempts, String userId) {
        if (attempts >= 5) { // Threshold de 5 tentativas
            SecurityAlert.AlertSeverity severity = attempts >= 10 ? 
                SecurityAlert.AlertSeverity.CRITICAL : SecurityAlert.AlertSeverity.HIGH;
            
            String description = String.format("Múltiplas tentativas de login falhadas: %d tentativas do IP %s", 
                attempts, ipAddress);
            
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("attempts", attempts);
            metadata.put("ipAddress", ipAddress);
            metadata.put("userId", userId != null ? userId : "unknown");
            metadata.put("threshold", 5);
            metadata.put("timestamp", LocalDateTime.now());
            
            createAlertAsync("MULTIPLE_FAILED_LOGINS", severity, description, userId, ipAddress, metadata);
        }
    }

    /**
     * Verifica e cria alerta para horário incomum de login
     */
    public void checkUnusualLoginTime(String userId, LocalDateTime loginTime, String ipAddress) {
        int hour = loginTime.getHour();
        
        // Horário incomum: entre 22h e 6h
        if (hour >= 22 || hour <= 6) {
            String description = String.format("Login em horário incomum: %s às %s", 
                userId, loginTime.format(java.time.format.DateTimeFormatter.ofPattern("HH:mm")));
            
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", userId);
            metadata.put("loginTime", loginTime);
            metadata.put("hour", hour);
            metadata.put("ipAddress", ipAddress);
            metadata.put("timestamp", LocalDateTime.now());
            
            createAlertAsync("UNUSUAL_LOGIN_TIME", SecurityAlert.AlertSeverity.MEDIUM, 
                description, userId, ipAddress, metadata);
        }
    }

    /**
     * Verifica e cria alerta para atividade suspeita
     */
    public void checkSuspiciousActivity(String userId, String activity, String ipAddress, Map<String, Object> details) {
        String description = String.format("Atividade suspeita detectada: %s para usuário %s", activity, userId);
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("activity", activity);
        metadata.put("ipAddress", ipAddress);
        metadata.put("details", details);
        metadata.put("timestamp", LocalDateTime.now());
        
        createAlertAsync("SUSPICIOUS_ACTIVITY", SecurityAlert.AlertSeverity.HIGH, 
            description, userId, ipAddress, metadata);
    }

    /**
     * Verifica e cria alerta para blacklist de token
     */
    public void checkTokenBlacklist(String userId, String token, String reason, String ipAddress) {
        String description = String.format("Token adicionado à blacklist: %s para usuário %s", reason, userId);
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("token", token.substring(0, Math.min(20, token.length())) + "...");
        metadata.put("reason", reason);
        metadata.put("ipAddress", ipAddress);
        metadata.put("timestamp", LocalDateTime.now());
        
        createAlertAsync("TOKEN_BLACKLIST", SecurityAlert.AlertSeverity.MEDIUM, 
            description, userId, ipAddress, metadata);
    }

    /**
     * Verifica e cria alerta para acesso negado
     */
    public void checkAccessDenied(String userId, String resource, String ipAddress, String reason) {
        String description = String.format("Acesso negado: %s para usuário %s", reason, userId);
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("resource", resource);
        metadata.put("ipAddress", ipAddress);
        metadata.put("reason", reason);
        metadata.put("timestamp", LocalDateTime.now());
        
        createAlertAsync("ACCESS_DENIED", SecurityAlert.AlertSeverity.MEDIUM, 
            description, userId, ipAddress, metadata);
    }

    /**
     * Verifica e cria alerta para padrões suspeitos
     */
    public void checkSuspiciousPatterns(String userId, String pattern, String ipAddress, Map<String, Object> details) {
        String description = String.format("Padrão suspeito detectado: %s para usuário %s", pattern, userId);
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", userId);
        metadata.put("pattern", pattern);
        metadata.put("ipAddress", ipAddress);
        metadata.put("details", details);
        metadata.put("timestamp", LocalDateTime.now());
        
        createAlertAsync("SUSPICIOUS_PATTERN", SecurityAlert.AlertSeverity.HIGH, 
            description, userId, ipAddress, metadata);
    }

    /**
     * Obtém alertas ativos
     */
    @Transactional(readOnly = true)
    public List<SecurityAlert> getActiveAlerts() {
        return securityAlertRepository.findByStatusOrderByCreatedAtDesc(SecurityAlert.AlertStatus.ACTIVE);
    }

    /**
     * Obtém alertas ativos com paginação
     */
    @Transactional(readOnly = true)
    public Page<SecurityAlert> getActiveAlerts(Pageable pageable) {
        return securityAlertRepository.findByStatusOrderByCreatedAtDesc(SecurityAlert.AlertStatus.ACTIVE, pageable);
    }

    /**
     * Obtém alertas críticos ativos
     */
    @Transactional(readOnly = true)
    public List<SecurityAlert> getCriticalActiveAlerts() {
        return securityAlertRepository.findCriticalActiveAlertsOrderByCreatedAtDesc();
    }

    /**
     * Obtém alertas por período
     */
    @Transactional(readOnly = true)
    public List<SecurityAlert> getAlertsByPeriod(LocalDateTime startDate, LocalDateTime endDate) {
        return securityAlertRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(startDate, endDate);
    }

    /**
     * Obtém alertas por usuário
     */
    @Transactional(readOnly = true)
    public List<SecurityAlert> getAlertsByUser(String userId) {
        return securityAlertRepository.findByUserIdOrderByCreatedAtDesc(userId);
    }

    /**
     * Obtém alertas por IP
     */
    @Transactional(readOnly = true)
    public List<SecurityAlert> getAlertsByIP(String ipAddress) {
        return securityAlertRepository.findByIpAddressOrderByCreatedAtDesc(ipAddress);
    }

    /**
     * Obtém alertas recentes (últimas 24 horas)
     */
    @Transactional(readOnly = true)
    public List<SecurityAlert> getRecentAlerts() {
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        return securityAlertRepository.findRecentAlerts(since);
    }

    /**
     * Obtém alertas por múltiplos critérios
     */
    @Transactional(readOnly = true)
    public Page<SecurityAlert> getAlertsByCriteria(SecurityAlert.AlertStatus status, 
                                                  SecurityAlert.AlertSeverity severity,
                                                  String alertType, String userId, String ipAddress,
                                                  LocalDateTime startDate, LocalDateTime endDate,
                                                  Pageable pageable) {
        return securityAlertRepository.findAlertsByCriteria(status, severity, alertType, userId, 
            ipAddress, startDate, endDate, pageable);
    }

    /**
     * Resolve um alerta
     */
    public SecurityAlert resolveAlert(UUID alertId, String resolvedBy, String resolutionNotes) {
        SecurityAlert alert = securityAlertRepository.findById(alertId)
            .orElseThrow(() -> new RuntimeException("Alert not found: " + alertId));
        
        alert.setStatus(SecurityAlert.AlertStatus.RESOLVED);
        alert.setResolvedAt(LocalDateTime.now());
        alert.setResolvedBy(resolvedBy);
        alert.setResolutionNotes(resolutionNotes);
        
        SecurityAlert savedAlert = securityAlertRepository.save(alert);
        
        logger.info("Alert resolved: {} by {}", alertId, resolvedBy);
        
        // Log de auditoria
        Map<String, Object> auditMetadata = new HashMap<>();
        auditMetadata.put("alertId", alertId.toString());
        auditMetadata.put("resolutionNotes", resolutionNotes);
        
        auditService.logEvent(resolvedBy, "SECURITY_ALERT_RESOLVED", 
            "Alerta de segurança resolvido: " + alert.getDescription(), 
            null, null, com.example.loginauthapi.domain.AuditEvent.AuditResult.SUCCESS,
            auditMetadata);
        
        return savedAlert;
    }

    /**
     * Descarta um alerta como falso positivo
     */
    public SecurityAlert dismissAlert(UUID alertId, String dismissedBy, String dismissalReason) {
        SecurityAlert alert = securityAlertRepository.findById(alertId)
            .orElseThrow(() -> new RuntimeException("Alert not found: " + alertId));
        
        alert.setStatus(SecurityAlert.AlertStatus.DISMISSED);
        alert.setResolvedAt(LocalDateTime.now());
        alert.setResolvedBy(dismissedBy);
        alert.setResolutionNotes(dismissalReason);
        
        SecurityAlert savedAlert = securityAlertRepository.save(alert);
        
        logger.info("Alert dismissed: {} by {}", alertId, dismissedBy);
        
        // Log de auditoria
        Map<String, Object> auditMetadata = new HashMap<>();
        auditMetadata.put("alertId", alertId.toString());
        auditMetadata.put("dismissalReason", dismissalReason);
        
        auditService.logEvent(dismissedBy, "SECURITY_ALERT_DISMISSED", 
            "Alerta de segurança descartado: " + alert.getDescription(), 
            null, null, com.example.loginauthapi.domain.AuditEvent.AuditResult.SUCCESS,
            auditMetadata);
        
        return savedAlert;
    }

    /**
     * Escala um alerta para nível superior
     */
    public SecurityAlert escalateAlert(UUID alertId, String escalatedBy, String escalationReason) {
        SecurityAlert alert = securityAlertRepository.findById(alertId)
            .orElseThrow(() -> new RuntimeException("Alert not found: " + alertId));
        
        alert.setStatus(SecurityAlert.AlertStatus.ESCALATED);
        alert.setResolvedBy(escalatedBy);
        alert.setResolutionNotes(escalationReason);
        
        SecurityAlert savedAlert = securityAlertRepository.save(alert);
        
        logger.info("Alert escalated: {} by {}", alertId, escalatedBy);
        
        // Log de auditoria
        Map<String, Object> auditMetadata = new HashMap<>();
        auditMetadata.put("alertId", alertId.toString());
        auditMetadata.put("escalationReason", escalationReason);
        
        auditService.logEvent(escalatedBy, "SECURITY_ALERT_ESCALATED", 
            "Alerta de segurança escalado: " + alert.getDescription(), 
            null, null, com.example.loginauthapi.domain.AuditEvent.AuditResult.SUCCESS,
            auditMetadata);
        
        return savedAlert;
    }

    /**
     * Obtém estatísticas de alertas
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getAlertStatistics() {
        List<Object[]> alertsByStatus = securityAlertRepository.countAlertsByStatus();
        List<Object[]> alertsBySeverity = securityAlertRepository.countAlertsBySeverity();
        List<Object[]> alertsByType = securityAlertRepository.countAlertsByType();
        List<Object[]> activeAlertsBySeverity = securityAlertRepository.countActiveAlertsBySeverity();
        
        Map<String, Object> statistics = new HashMap<>();
        statistics.put("alertsByStatus", alertsByStatus);
        statistics.put("alertsBySeverity", alertsBySeverity);
        statistics.put("alertsByType", alertsByType);
        statistics.put("activeAlertsBySeverity", activeAlertsBySeverity);
        statistics.put("totalAlerts", securityAlertRepository.count());
        statistics.put("activeAlerts", securityAlertRepository.findByStatusOrderByCreatedAtDesc(SecurityAlert.AlertStatus.ACTIVE).size());
        statistics.put("criticalAlerts", securityAlertRepository.findCriticalActiveAlertsOrderByCreatedAtDesc().size());
        statistics.put("timestamp", LocalDateTime.now());
        
        return statistics;
    }

    /**
     * Limpa alertas antigos (para manutenção)
     */
    public int cleanupOldAlerts(int daysToKeep) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysToKeep);
        int deletedCount = securityAlertRepository.deleteOldAlerts(cutoffDate);
        logger.info("Cleaned up {} old security alerts older than {} days", deletedCount, daysToKeep);
        return deletedCount;
    }

    /**
     * Verifica se há alertas similares recentes
     */
    @Transactional(readOnly = true)
    public boolean hasSimilarRecentAlerts(String alertType, String ipAddress, int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        List<SecurityAlert> similarAlerts = securityAlertRepository.findSimilarAlerts(alertType, ipAddress, since);
        return !similarAlerts.isEmpty();
    }
}
