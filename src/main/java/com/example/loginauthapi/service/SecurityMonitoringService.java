package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.AuditEvent;
import com.example.loginauthapi.dto.SecurityAlertDTO;
import com.example.loginauthapi.dto.SecurityMetricsDTO;
import com.example.loginauthapi.dto.SuspiciousActivityDTO;
import com.example.loginauthapi.repositories.AuditRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Serviço de monitoramento de segurança
 * 
 * Fornece métricas e análises de segurança em tempo real
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class SecurityMonitoringService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityMonitoringService.class);

    private final AuditRepository auditRepository;

    /**
     * Obtém métricas de segurança completas
     */
    public SecurityMetricsDTO getSecurityMetrics() {
        logger.debug("Generating security metrics");

        LocalDateTime todayStart = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);
        LocalDateTime now = LocalDateTime.now();

        // Contar eventos do dia
        long totalLoginsToday = countEventsByTypeAndPeriod("LOGIN_SUCCESS", todayStart, now);
        long failedLoginsToday = countEventsByTypeAndPeriod("LOGIN_FAILURE", todayStart, now);
        long suspiciousActivitiesToday = countEventsByResultAndPeriod(AuditEvent.AuditResult.SUSPICIOUS, todayStart, now);
        long blacklistedTokensToday = countEventsByTypeAndPeriod("TOKEN_BLACKLIST", todayStart, now);

        // Calcular score de segurança
        double securityScore = calculateSecurityScore(totalLoginsToday, failedLoginsToday, suspiciousActivitiesToday);

        // Obter alertas ativos (simulado por enquanto)
        List<SecurityAlertDTO> activeAlerts = getActiveAlerts();

        // Obter métricas por hora
        Map<String, Long> loginAttemptsByHour = getLoginAttemptsByHour();
        Map<String, Long> failedLoginsByIP = getFailedLoginsByIP();

        // Obter atividades suspeitas
        List<SuspiciousActivityDTO> suspiciousActivities = getSuspiciousActivities();

        SecurityMetricsDTO metrics = new SecurityMetricsDTO(
            totalLoginsToday, failedLoginsToday, suspiciousActivitiesToday, 
            blacklistedTokensToday, securityScore, activeAlerts
        );

        metrics.setLoginAttemptsByHour(loginAttemptsByHour);
        metrics.setFailedLoginsByIP(failedLoginsByIP);
        metrics.setSuspiciousActivities(suspiciousActivities);
        metrics.setLastUpdated(now);

        logger.debug("Security metrics generated successfully");
        return metrics;
    }

    /**
     * Obtém eventos de segurança recentes
     */
    public List<AuditEvent> getRecentSecurityEvents(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return auditRepository.findRecentEvents(since)
            .stream()
            .filter(event -> isSecurityEvent(event))
            .collect(Collectors.toList());
    }

    /**
     * Obtém tentativas de login por hora
     */
    public Map<String, Long> getLoginAttemptsByHour() {
        LocalDateTime todayStart = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);
        LocalDateTime now = LocalDateTime.now();

        Map<String, Long> attemptsByHour = new HashMap<>();

        for (int hour = 0; hour < 24; hour++) {
            LocalDateTime hourStart = todayStart.plusHours(hour);
            LocalDateTime hourEnd = hourStart.plusHours(1);

            if (hourEnd.isAfter(now)) {
                break;
            }

            long attempts = countEventsByTypeAndPeriod("LOGIN_SUCCESS", hourStart, hourEnd) +
                           countEventsByTypeAndPeriod("LOGIN_FAILURE", hourStart, hourEnd);

            attemptsByHour.put(String.format("%02d:00", hour), attempts);
        }

        return attemptsByHour;
    }

    /**
     * Obtém logins falhados por IP
     */
    public Map<String, Long> getFailedLoginsByIP() {
        LocalDateTime todayStart = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);
        LocalDateTime now = LocalDateTime.now();

        List<AuditEvent> failedLogins = auditRepository.findByTimestampBetweenOrderByTimestampDesc(todayStart, now)
            .stream()
            .filter(event -> "LOGIN_FAILURE".equals(event.getEventType()))
            .collect(Collectors.toList());

        return failedLogins.stream()
            .collect(Collectors.groupingBy(
                event -> event.getIpAddress() != null ? event.getIpAddress() : "unknown",
                Collectors.counting()
            ))
            .entrySet()
            .stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10) // Top 10 IPs com mais falhas
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue,
                (e1, e2) -> e1,
                LinkedHashMap::new
            ));
    }

    /**
     * Obtém atividades suspeitas
     */
    public List<SuspiciousActivityDTO> getSuspiciousActivities() {
        LocalDateTime todayStart = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0).withNano(0);
        LocalDateTime now = LocalDateTime.now();

        List<AuditEvent> suspiciousEvents = auditRepository.findSuspiciousEventsByPeriodOrderByTimestampDesc(todayStart, now);

        return suspiciousEvents.stream()
            .map(this::convertToSuspiciousActivityDTO)
            .collect(Collectors.toList());
    }

    /**
     * Obtém estatísticas de segurança por período
     */
    public Map<String, Object> getSecurityStatistics(LocalDateTime startDate, LocalDateTime endDate) {
        Map<String, Object> stats = new HashMap<>();

        // Estatísticas básicas
        stats.put("totalEvents", auditRepository.count());
        stats.put("suspiciousEvents", auditRepository.findSuspiciousEventsByPeriodOrderByTimestampDesc(startDate, endDate).size());
        stats.put("failedLogins", auditRepository.findLoginEventsByPeriodOrderByTimestampDesc(startDate, endDate)
            .stream()
            .filter(event -> "LOGIN_FAILURE".equals(event.getEventType()))
            .count());

        // Eventos por tipo
        List<Object[]> eventsByType = auditRepository.countEventsByType();
        stats.put("eventsByType", eventsByType);

        // Eventos por resultado
        List<Object[]> eventsByResult = auditRepository.countEventsByResult();
        stats.put("eventsByResult", eventsByResult);

        // IPs mais ativos
        List<Object[]> eventsByIp = auditRepository.countEventsByIpAddress();
        stats.put("eventsByIp", eventsByIp);

        stats.put("generatedAt", LocalDateTime.now());
        return stats;
    }

    /**
     * Detecta padrões suspeitos
     */
    public List<String> detectSuspiciousPatterns() {
        List<String> patterns = new ArrayList<>();

        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);

        // Padrão: Muitas tentativas de login falhadas do mesmo IP
        Map<String, Long> failedLoginsByIP = getFailedLoginsByIP();
        failedLoginsByIP.entrySet().stream()
            .filter(entry -> entry.getValue() > 10) // Mais de 10 falhas
            .forEach(entry -> patterns.add(String.format("IP %s com %d tentativas de login falhadas", 
                entry.getKey(), entry.getValue())));

        // Padrão: Muitas atividades suspeitas do mesmo usuário
        List<AuditEvent> suspiciousEvents = auditRepository.findSuspiciousEventsByPeriodOrderByTimestampDesc(last24Hours, LocalDateTime.now());
        Map<String, Long> suspiciousByUser = suspiciousEvents.stream()
            .collect(Collectors.groupingBy(
                event -> event.getUserId() != null ? event.getUserId() : "unknown",
                Collectors.counting()
            ));

        suspiciousByUser.entrySet().stream()
            .filter(entry -> entry.getValue() > 5) // Mais de 5 atividades suspeitas
            .forEach(entry -> patterns.add(String.format("Usuário %s com %d atividades suspeitas", 
                entry.getKey(), entry.getValue())));

        return patterns;
    }

    /**
     * Conta eventos por tipo e período
     */
    private long countEventsByTypeAndPeriod(String eventType, LocalDateTime start, LocalDateTime end) {
        return auditRepository.findByTimestampBetweenOrderByTimestampDesc(start, end)
            .stream()
            .filter(event -> eventType.equals(event.getEventType()))
            .count();
    }

    /**
     * Conta eventos por resultado e período
     */
    private long countEventsByResultAndPeriod(AuditEvent.AuditResult result, LocalDateTime start, LocalDateTime end) {
        return auditRepository.findByTimestampBetweenOrderByTimestampDesc(start, end)
            .stream()
            .filter(event -> result.equals(event.getResult()))
            .count();
    }

    /**
     * Calcula score de segurança (0-100)
     */
    private double calculateSecurityScore(long totalLogins, long failedLogins, long suspiciousActivities) {
        if (totalLogins == 0) {
            return 100.0; // Sem atividade = score perfeito
        }

        double failureRate = (double) failedLogins / totalLogins;
        double suspiciousRate = (double) suspiciousActivities / totalLogins;

        // Score base: 100
        double score = 100.0;

        // Penalizar por taxa de falha alta
        score -= failureRate * 30; // Até 30 pontos de penalidade

        // Penalizar por atividades suspeitas
        score -= suspiciousRate * 50; // Até 50 pontos de penalidade

        // Garantir que o score esteja entre 0 e 100
        return Math.max(0.0, Math.min(100.0, score));
    }

    /**
     * Verifica se é um evento de segurança
     */
    private boolean isSecurityEvent(AuditEvent event) {
        String eventType = event.getEventType();
        return eventType.contains("LOGIN") || 
               eventType.contains("SUSPICIOUS") || 
               eventType.contains("BLACKLIST") ||
               eventType.contains("ACCESS_DENIED");
    }

    /**
     * Converte AuditEvent para SuspiciousActivityDTO
     */
    private SuspiciousActivityDTO convertToSuspiciousActivityDTO(AuditEvent event) {
        return new SuspiciousActivityDTO(
            event.getId().toString(),
            event.getUserId(),
            event.getEventType(),
            event.getEventDescription(),
            event.getIpAddress(),
            event.getTimestamp(),
            determineSeverity(event),
            event.getMetadata()
        );
    }

    /**
     * Determina severidade baseada no evento
     */
    private String determineSeverity(AuditEvent event) {
        if (event.getResult() == AuditEvent.AuditResult.SUSPICIOUS) {
            return "HIGH";
        } else if (event.getResult() == AuditEvent.AuditResult.BLOCKED) {
            return "CRITICAL";
        } else if (event.getResult() == AuditEvent.AuditResult.FAILURE) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }

    /**
     * Obtém alertas ativos (simulado por enquanto)
     */
    private List<SecurityAlertDTO> getActiveAlerts() {
        // Por enquanto, retorna alertas baseados em eventos suspeitos recentes
        List<AuditEvent> suspiciousEvents = auditRepository.findSuspiciousEventsOrderByTimestampDesc()
            .stream()
            .limit(5) // Últimos 5 eventos suspeitos
            .collect(Collectors.toList());

        return suspiciousEvents.stream()
            .map(event -> new SecurityAlertDTO(
                event.getId().toString(),
                "SUSPICIOUS_ACTIVITY",
                determineSeverity(event),
                event.getEventDescription(),
                event.getUserId(),
                event.getIpAddress(),
                event.getTimestamp(),
                "ACTIVE"
            ))
            .collect(Collectors.toList());
    }
}
