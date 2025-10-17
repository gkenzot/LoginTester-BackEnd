package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.AuditEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Motor de regras para detecção de alertas de segurança
 * 
 * Avalia eventos e padrões para gerar alertas de segurança
 */
@Component
@RequiredArgsConstructor
public class AlertRulesEngine {

    private static final Logger logger = LoggerFactory.getLogger(AlertRulesEngine.class);

    private final SecurityAlertService securityAlertService;

    // Contadores para detecção de padrões
    private final Map<String, AtomicInteger> failedLoginCounters = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> suspiciousActivityCounters = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastActivityTime = new ConcurrentHashMap<>();

    /**
     * Avalia tentativas de login para detectar padrões suspeitos
     */
    public void evaluateLoginAttempts(String ipAddress, String userId, boolean success, String userAgent) {
        String key = ipAddress + ":" + (userId != null ? userId : "anonymous");
        
        if (!success) {
            // Incrementar contador de falhas
            failedLoginCounters.computeIfAbsent(key, k -> new AtomicInteger(0)).incrementAndGet();
            
            // Verificar se excedeu o threshold
            int failures = failedLoginCounters.get(key).get();
            if (failures >= 5) {
                logger.warn("Multiple failed login attempts detected: {} failures for {}", failures, key);
                securityAlertService.checkMultipleFailedLogins(ipAddress, failures, userId);
                
                // Reset contador após alerta
                failedLoginCounters.put(key, new AtomicInteger(0));
            }
        } else {
            // Reset contador em caso de sucesso
            failedLoginCounters.put(key, new AtomicInteger(0));
            
            // Verificar horário incomum de login
            LocalDateTime now = LocalDateTime.now();
            securityAlertService.checkUnusualLoginTime(userId != null ? userId : "unknown", now, ipAddress);
        }
        
        // Atualizar último tempo de atividade
        lastActivityTime.put(key, LocalDateTime.now());
    }

    /**
     * Avalia atividades suspeitas
     */
    public void evaluateUnusualActivity(String userId, String activity, String ipAddress, Map<String, Object> details) {
        String key = userId + ":" + activity;
        
        // Incrementar contador de atividades suspeitas
        suspiciousActivityCounters.computeIfAbsent(key, k -> new AtomicInteger(0)).incrementAndGet();
        
        int suspiciousCount = suspiciousActivityCounters.get(key).get();
        
        // Verificar se excedeu o threshold
        if (suspiciousCount >= 3) {
            logger.warn("Suspicious activity pattern detected: {} occurrences of {} for user {}", 
                suspiciousCount, activity, userId);
            
            securityAlertService.checkSuspiciousActivity(userId, activity, ipAddress, details);
            
            // Reset contador após alerta
            suspiciousActivityCounters.put(key, new AtomicInteger(0));
        }
    }

    /**
     * Avalia padrões suspeitos baseados em eventos de auditoria
     */
    public void evaluateSuspiciousPatterns(List<AuditEvent> events) {
        if (events == null || events.isEmpty()) {
            return;
        }
        
        // Agrupar eventos por IP
        Map<String, List<AuditEvent>> eventsByIP = events.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                event -> event.getIpAddress() != null ? event.getIpAddress() : "unknown"
            ));
        
        // Analisar cada IP
        eventsByIP.forEach((ip, ipEvents) -> {
            analyzeIPPatterns(ip, ipEvents);
        });
        
        // Agrupar eventos por usuário
        Map<String, List<AuditEvent>> eventsByUser = events.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                event -> event.getUserId() != null ? event.getUserId() : "unknown"
            ));
        
        // Analisar cada usuário
        eventsByUser.forEach((userId, userEvents) -> {
            analyzeUserPatterns(userId, userEvents);
        });
    }

    /**
     * Avalia blacklist de tokens
     */
    public void evaluateTokenBlacklist(String userId, String token, String reason, String ipAddress) {
        logger.info("Token blacklist event: {} for user {} from IP {}", reason, userId, ipAddress);
        
        securityAlertService.checkTokenBlacklist(userId, token, reason, ipAddress);
        
        // Se for por motivo suspeito, criar alerta adicional
        if ("compromised".equals(reason) || "suspicious_activity".equals(reason)) {
            Map<String, Object> details = new HashMap<>();
            details.put("token", token.substring(0, Math.min(20, token.length())) + "...");
            details.put("reason", reason);
            details.put("timestamp", LocalDateTime.now());
            
            securityAlertService.checkSuspiciousPatterns(userId, "TOKEN_COMPROMISED", ipAddress, details);
        }
    }

    /**
     * Analisa padrões por IP
     */
    private void analyzeIPPatterns(String ip, List<AuditEvent> events) {
        // Verificar múltiplas falhas de login
        long failedLogins = events.stream()
            .filter(event -> "LOGIN_FAILURE".equals(event.getEventType()))
            .count();
        
        if (failedLogins >= 10) {
            logger.warn("High number of failed logins from IP {}: {}", ip, failedLogins);
            securityAlertService.checkMultipleFailedLogins(ip, (int) failedLogins, null);
        }
        
        // Verificar múltiplas atividades suspeitas
        long suspiciousActivities = events.stream()
            .filter(event -> event.getResult() == AuditEvent.AuditResult.SUSPICIOUS)
            .count();
        
        if (suspiciousActivities >= 5) {
            logger.warn("High number of suspicious activities from IP {}: {}", ip, suspiciousActivities);
            
            Map<String, Object> details = new HashMap<>();
            details.put("ip", ip);
            details.put("suspiciousCount", suspiciousActivities);
            details.put("totalEvents", events.size());
            details.put("timestamp", LocalDateTime.now());
            
            securityAlertService.checkSuspiciousPatterns("unknown", "MULTIPLE_SUSPICIOUS_ACTIVITIES", ip, details);
        }
        
        // Verificar acesso negado múltiplo
        long accessDenied = events.stream()
            .filter(event -> "ACCESS_DENIED".equals(event.getEventType()))
            .count();
        
        if (accessDenied >= 5) {
            logger.warn("High number of access denied from IP {}: {}", ip, accessDenied);
            securityAlertService.checkAccessDenied("unknown", "multiple_resources", ip, 
                "Multiple access denied attempts");
        }
    }

    /**
     * Analisa padrões por usuário
     */
    private void analyzeUserPatterns(String userId, List<AuditEvent> events) {
        if ("unknown".equals(userId)) {
            return; // Pular usuários desconhecidos
        }
        
        // Verificar múltiplas atividades suspeitas
        long suspiciousActivities = events.stream()
            .filter(event -> event.getResult() == AuditEvent.AuditResult.SUSPICIOUS)
            .count();
        
        if (suspiciousActivities >= 3) {
            logger.warn("High number of suspicious activities for user {}: {}", userId, suspiciousActivities);
            
            Map<String, Object> details = new HashMap<>();
            details.put("userId", userId);
            details.put("suspiciousCount", suspiciousActivities);
            details.put("totalEvents", events.size());
            details.put("timestamp", LocalDateTime.now());
            
            securityAlertService.checkSuspiciousPatterns(userId, "MULTIPLE_SUSPICIOUS_ACTIVITIES", 
                events.get(0).getIpAddress(), details);
        }
        
        // Verificar múltiplos logins em horários incomuns
        long unusualLogins = events.stream()
            .filter(event -> "LOGIN_SUCCESS".equals(event.getEventType()))
            .filter(event -> {
                int hour = event.getTimestamp().getHour();
                return hour >= 22 || hour <= 6;
            })
            .count();
        
        if (unusualLogins >= 3) {
            logger.warn("Multiple unusual login times for user {}: {}", userId, unusualLogins);
            
            Map<String, Object> details = new HashMap<>();
            details.put("userId", userId);
            details.put("unusualLoginCount", unusualLogins);
            details.put("timestamp", LocalDateTime.now());
            
            securityAlertService.checkSuspiciousPatterns(userId, "MULTIPLE_UNUSUAL_LOGINS", 
                events.get(0).getIpAddress(), details);
        }
    }

    /**
     * Limpa contadores antigos (para evitar vazamentos de memória)
     */
    public void cleanupOldCounters() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        
        // Limpar contadores de login falhado
        failedLoginCounters.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            LocalDateTime lastTime = lastActivityTime.get(key);
            return lastTime != null && lastTime.isBefore(cutoff);
        });
        
        // Limpar contadores de atividades suspeitas
        suspiciousActivityCounters.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            LocalDateTime lastTime = lastActivityTime.get(key);
            return lastTime != null && lastTime.isBefore(cutoff);
        });
        
        // Limpar timestamps antigos
        lastActivityTime.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
        
        logger.debug("Cleaned up old alert counters");
    }

    /**
     * Obtém estatísticas dos contadores
     */
    public Map<String, Object> getCounterStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("failedLoginCounters", failedLoginCounters.size());
        stats.put("suspiciousActivityCounters", suspiciousActivityCounters.size());
        stats.put("lastActivityTime", lastActivityTime.size());
        stats.put("timestamp", LocalDateTime.now());
        return stats;
    }

    /**
     * Reset contadores para um IP específico
     */
    public void resetCountersForIP(String ipAddress) {
        failedLoginCounters.entrySet().removeIf(entry -> entry.getKey().startsWith(ipAddress + ":"));
        suspiciousActivityCounters.entrySet().removeIf(entry -> entry.getKey().contains(ipAddress));
        lastActivityTime.entrySet().removeIf(entry -> entry.getKey().startsWith(ipAddress + ":"));
        
        logger.info("Reset counters for IP: {}", ipAddress);
    }

    /**
     * Reset contadores para um usuário específico
     */
    public void resetCountersForUser(String userId) {
        failedLoginCounters.entrySet().removeIf(entry -> entry.getKey().endsWith(":" + userId));
        suspiciousActivityCounters.entrySet().removeIf(entry -> entry.getKey().startsWith(userId + ":"));
        lastActivityTime.entrySet().removeIf(entry -> entry.getKey().endsWith(":" + userId));
        
        logger.info("Reset counters for user: {}", userId);
    }
}
