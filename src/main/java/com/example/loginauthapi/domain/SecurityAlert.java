package com.example.loginauthapi.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Entidade para alertas de segurança
 * 
 * Registra alertas de segurança gerados pelo sistema
 */
@Entity
@Table(name = "security_alerts", indexes = {
    @Index(name = "idx_security_alert_type", columnList = "alertType"),
    @Index(name = "idx_security_alert_severity", columnList = "severity"),
    @Index(name = "idx_security_alert_status", columnList = "status"),
    @Index(name = "idx_security_alert_user_id", columnList = "userId"),
    @Index(name = "idx_security_alert_created_at", columnList = "createdAt")
})
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "alert_type", nullable = false, length = 50)
    private String alertType;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 20)
    private AlertSeverity severity;

    @Column(name = "description", nullable = false, length = 1000)
    private String description;

    @Column(name = "user_id", nullable = true)
    private String userId;

    @Column(name = "ip_address", nullable = true, length = 45)
    private String ipAddress;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "resolved_at", nullable = true)
    private LocalDateTime resolvedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private AlertStatus status;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    @Column(name = "resolved_by", nullable = true)
    private String resolvedBy;

    @Column(name = "resolution_notes", nullable = true, length = 1000)
    private String resolutionNotes;

    // Construtores
    public SecurityAlert() {}

    public SecurityAlert(String alertType, AlertSeverity severity, String description,
                        String userId, String ipAddress, Map<String, Object> metadata) {
        this.alertType = alertType;
        this.severity = severity;
        this.description = description;
        this.userId = userId;
        this.ipAddress = ipAddress;
        this.status = AlertStatus.ACTIVE;
        this.metadata = metadata;
    }

    // Getters e Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getAlertType() {
        return alertType;
    }

    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    public AlertSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(AlertSeverity severity) {
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

    public AlertStatus getStatus() {
        return status;
    }

    public void setStatus(AlertStatus status) {
        this.status = status;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public String getResolvedBy() {
        return resolvedBy;
    }

    public void setResolvedBy(String resolvedBy) {
        this.resolvedBy = resolvedBy;
    }

    public String getResolutionNotes() {
        return resolutionNotes;
    }

    public void setResolutionNotes(String resolutionNotes) {
        this.resolutionNotes = resolutionNotes;
    }

    @Override
    public String toString() {
        return "SecurityAlert{" +
                "id=" + id +
                ", alertType='" + alertType + '\'' +
                ", severity=" + severity +
                ", description='" + description + '\'' +
                ", userId='" + userId + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", createdAt=" + createdAt +
                ", status=" + status +
                '}';
    }

    /**
     * Enum para severidade do alerta
     */
    public enum AlertSeverity {
        LOW("Baixa", "Alerta de baixa prioridade"),
        MEDIUM("Média", "Alerta de média prioridade"),
        HIGH("Alta", "Alerta de alta prioridade"),
        CRITICAL("Crítica", "Alerta crítico que requer atenção imediata");

        private final String displayName;
        private final String description;

        AlertSeverity(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Enum para status do alerta
     */
    public enum AlertStatus {
        ACTIVE("Ativo", "Alerta ativo aguardando resolução"),
        RESOLVED("Resolvido", "Alerta foi resolvido"),
        DISMISSED("Descartado", "Alerta foi descartado como falso positivo"),
        ESCALATED("Escalado", "Alerta foi escalado para nível superior");

        private final String displayName;
        private final String description;

        AlertStatus(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getDescription() {
            return description;
        }
    }
}
