package com.example.loginauthapi.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * DTO para métricas de segurança
 */
public class SecurityMetricsDTO {
    
    private long totalLoginsToday;
    private long failedLoginsToday;
    private long suspiciousActivitiesToday;
    private long blacklistedTokensToday;
    private double securityScore;
    private List<SecurityAlertDTO> activeAlerts;
    private Map<String, Long> loginAttemptsByHour;
    private Map<String, Long> failedLoginsByIP;
    private List<SuspiciousActivityDTO> suspiciousActivities;
    private LocalDateTime lastUpdated;

    // Construtores
    public SecurityMetricsDTO() {}

    public SecurityMetricsDTO(long totalLoginsToday, long failedLoginsToday, 
                            long suspiciousActivitiesToday, long blacklistedTokensToday,
                            double securityScore, List<SecurityAlertDTO> activeAlerts) {
        this.totalLoginsToday = totalLoginsToday;
        this.failedLoginsToday = failedLoginsToday;
        this.suspiciousActivitiesToday = suspiciousActivitiesToday;
        this.blacklistedTokensToday = blacklistedTokensToday;
        this.securityScore = securityScore;
        this.activeAlerts = activeAlerts;
        this.lastUpdated = LocalDateTime.now();
    }

    // Getters e Setters
    public long getTotalLoginsToday() {
        return totalLoginsToday;
    }

    public void setTotalLoginsToday(long totalLoginsToday) {
        this.totalLoginsToday = totalLoginsToday;
    }

    public long getFailedLoginsToday() {
        return failedLoginsToday;
    }

    public void setFailedLoginsToday(long failedLoginsToday) {
        this.failedLoginsToday = failedLoginsToday;
    }

    public long getSuspiciousActivitiesToday() {
        return suspiciousActivitiesToday;
    }

    public void setSuspiciousActivitiesToday(long suspiciousActivitiesToday) {
        this.suspiciousActivitiesToday = suspiciousActivitiesToday;
    }

    public long getBlacklistedTokensToday() {
        return blacklistedTokensToday;
    }

    public void setBlacklistedTokensToday(long blacklistedTokensToday) {
        this.blacklistedTokensToday = blacklistedTokensToday;
    }

    public double getSecurityScore() {
        return securityScore;
    }

    public void setSecurityScore(double securityScore) {
        this.securityScore = securityScore;
    }

    public List<SecurityAlertDTO> getActiveAlerts() {
        return activeAlerts;
    }

    public void setActiveAlerts(List<SecurityAlertDTO> activeAlerts) {
        this.activeAlerts = activeAlerts;
    }

    public Map<String, Long> getLoginAttemptsByHour() {
        return loginAttemptsByHour;
    }

    public void setLoginAttemptsByHour(Map<String, Long> loginAttemptsByHour) {
        this.loginAttemptsByHour = loginAttemptsByHour;
    }

    public Map<String, Long> getFailedLoginsByIP() {
        return failedLoginsByIP;
    }

    public void setFailedLoginsByIP(Map<String, Long> failedLoginsByIP) {
        this.failedLoginsByIP = failedLoginsByIP;
    }

    public List<SuspiciousActivityDTO> getSuspiciousActivities() {
        return suspiciousActivities;
    }

    public void setSuspiciousActivities(List<SuspiciousActivityDTO> suspiciousActivities) {
        this.suspiciousActivities = suspiciousActivities;
    }

    public LocalDateTime getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(LocalDateTime lastUpdated) {
        this.lastUpdated = lastUpdated;
    }
}
