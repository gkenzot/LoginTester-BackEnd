package com.example.loginauthapi.dto;

import java.time.LocalDateTime;

/**
 * DTO para alertas de segurança
 */
public class SecurityAlertDTO {
    
    private String id;
    private String alertType;
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL
    private String description;
    private String userId;
    private String ipAddress;
    private LocalDateTime createdAt;
    private LocalDateTime resolvedAt;
    private String status; // ACTIVE, RESOLVED, DISMISSED

    // Construtores
    public SecurityAlertDTO() {}

    public SecurityAlertDTO(String id, String alertType, String severity, String description,
                          String userId, String ipAddress, LocalDateTime createdAt, String status) {
        this.id = id;
        this.alertType = alertType;
        this.severity = severity;
        this.description = description;
        this.userId = userId;
        this.ipAddress = ipAddress;
        this.createdAt = createdAt;
        this.status = status;
    }

    // Getters e Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAlertType() {
        return alertType;
    }

    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(LocalDateTime resolvedAt) {
        this.resolvedAt = resolvedAt;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
