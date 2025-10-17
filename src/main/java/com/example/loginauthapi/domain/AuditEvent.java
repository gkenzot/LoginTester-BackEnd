package com.example.loginauthapi.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Entidade para eventos de auditoria
 * 
 * Registra todas as operações críticas do sistema para fins de segurança e conformidade
 */
@Entity
@Table(name = "audit_events", indexes = {
    @Index(name = "idx_audit_user_id", columnList = "userId"),
    @Index(name = "idx_audit_event_type", columnList = "eventType"),
    @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
    @Index(name = "idx_audit_result", columnList = "result"),
    @Index(name = "idx_audit_ip_address", columnList = "ipAddress")
})
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = true)
    private String userId;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @Column(name = "event_description", nullable = false, length = 500)
    private String eventDescription;

    @Column(name = "ip_address", nullable = true, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", nullable = true, length = 1000)
    private String userAgent;

    @CreationTimestamp
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Enumerated(EnumType.STRING)
    @Column(name = "result", nullable = false, length = 20)
    private AuditResult result;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    @Column(name = "session_id", nullable = true, length = 100)
    private String sessionId;

    @Column(name = "request_id", nullable = true, length = 100)
    private String requestId;

    // Construtores
    public AuditEvent() {}

    public AuditEvent(String userId, String eventType, String eventDescription, 
                     String ipAddress, String userAgent, AuditResult result) {
        this.userId = userId;
        this.eventType = eventType;
        this.eventDescription = eventDescription;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.result = result;
    }

    // Getters e Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getEventDescription() {
        return eventDescription;
    }

    public void setEventDescription(String eventDescription) {
        this.eventDescription = eventDescription;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public AuditResult getResult() {
        return result;
    }

    public void setResult(AuditResult result) {
        this.result = result;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    @Override
    public String toString() {
        return "AuditEvent{" +
                "id=" + id +
                ", userId='" + userId + '\'' +
                ", eventType='" + eventType + '\'' +
                ", eventDescription='" + eventDescription + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", timestamp=" + timestamp +
                ", result=" + result +
                '}';
    }

    /**
     * Enum para resultados de auditoria
     */
    public enum AuditResult {
        SUCCESS("Operação realizada com sucesso"),
        FAILURE("Operação falhou"),
        SUSPICIOUS("Atividade suspeita detectada"),
        BLOCKED("Operação bloqueada"),
        WARNING("Operação com aviso");

        private final String description;

        AuditResult(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}
