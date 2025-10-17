package com.example.loginauthapi.dto;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * DTO para atividades suspeitas
 */
public class SuspiciousActivityDTO {
    
    private String id;
    private String userId;
    private String activityType;
    private String description;
    private String ipAddress;
    private LocalDateTime timestamp;
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL
    private Map<String, Object> details;

    // Construtores
    public SuspiciousActivityDTO() {}

    public SuspiciousActivityDTO(String id, String userId, String activityType, String description,
                                String ipAddress, LocalDateTime timestamp, String severity, Map<String, Object> details) {
        this.id = id;
        this.userId = userId;
        this.activityType = activityType;
        this.description = description;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.severity = severity;
        this.details = details;
    }

    // Getters e Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getActivityType() {
        return activityType;
    }

    public void setActivityType(String activityType) {
        this.activityType = activityType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public void setDetails(Map<String, Object> details) {
        this.details = details;
    }
}
