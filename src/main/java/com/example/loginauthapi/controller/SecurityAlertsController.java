package com.example.loginauthapi.controller;

import com.example.loginauthapi.domain.SecurityAlert;
import com.example.loginauthapi.service.AuthService;
import com.example.loginauthapi.service.SecurityAlertService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Controller para gerenciar alertas de segurança
 * 
 * Fornece endpoints para consultar e gerenciar alertas de segurança (apenas ADMIN)
 */
@RestController
@RequestMapping("/api/alerts")
@Tag(name = "Alertas de Segurança", description = "Endpoints para gerenciar alertas de segurança")
@RequiredArgsConstructor
public class SecurityAlertsController {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAlertsController.class);

    private final SecurityAlertService securityAlertService;
    private final AuthService authService;

    @GetMapping("/active")
    @Operation(summary = "Alertas ativos", description = "Retorna alertas de segurança ativos (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Alertas retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<SecurityAlert>> getActiveAlerts(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Active security alerts request");

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Obter alertas ativos
            List<SecurityAlert> activeAlerts = securityAlertService.getActiveAlerts();

            logger.info("Active security alerts retrieved successfully: {} alerts", activeAlerts.size());
            return ResponseEntity.ok().body(activeAlerts);

        } catch (Exception e) {
            logger.error("Error retrieving active security alerts: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/critical")
    @Operation(summary = "Alertas críticos", description = "Retorna alertas críticos ativos (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Alertas críticos retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<SecurityAlert>> getCriticalAlerts(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Critical security alerts request");

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Obter alertas críticos
            List<SecurityAlert> criticalAlerts = securityAlertService.getCriticalActiveAlerts();

            logger.info("Critical security alerts retrieved successfully: {} alerts", criticalAlerts.size());
            return ResponseEntity.ok().body(criticalAlerts);

        } catch (Exception e) {
            logger.error("Error retrieving critical security alerts: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/recent")
    @Operation(summary = "Alertas recentes", description = "Retorna alertas de segurança recentes (últimas 24h) (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Alertas recentes retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<SecurityAlert>> getRecentAlerts(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Recent security alerts request");

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Obter alertas recentes
            List<SecurityAlert> recentAlerts = securityAlertService.getRecentAlerts();

            logger.info("Recent security alerts retrieved successfully: {} alerts", recentAlerts.size());
            return ResponseEntity.ok().body(recentAlerts);

        } catch (Exception e) {
            logger.error("Error retrieving recent security alerts: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/search")
    @Operation(summary = "Buscar alertas", description = "Busca alertas com filtros (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Alertas retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<Page<SecurityAlert>> searchAlerts(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "Número da página (0-based)") @RequestParam(defaultValue = "0") int page,
        @Parameter(description = "Tamanho da página") @RequestParam(defaultValue = "20") int size,
        @Parameter(description = "Filtrar por status") @RequestParam(required = false) SecurityAlert.AlertStatus status,
        @Parameter(description = "Filtrar por severidade") @RequestParam(required = false) SecurityAlert.AlertSeverity severity,
        @Parameter(description = "Filtrar por tipo") @RequestParam(required = false) String alertType,
        @Parameter(description = "Filtrar por usuário") @RequestParam(required = false) String userId,
        @Parameter(description = "Filtrar por IP") @RequestParam(required = false) String ipAddress,
        @Parameter(description = "Data início (yyyy-MM-dd HH:mm:ss)") @RequestParam(required = false) String startDate,
        @Parameter(description = "Data fim (yyyy-MM-dd HH:mm:ss)") @RequestParam(required = false) String endDate) {

        logger.info("Security alerts search request");

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Configurar paginação e ordenação
            Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
            Pageable pageable = PageRequest.of(page, size, sort);

            // Converter datas se fornecidas
            LocalDateTime startDateTime = null;
            LocalDateTime endDateTime = null;
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            if (startDate != null && !startDate.isEmpty()) {
                startDateTime = LocalDateTime.parse(startDate, formatter);
            }
            if (endDate != null && !endDate.isEmpty()) {
                endDateTime = LocalDateTime.parse(endDate, formatter);
            }

            // Buscar alertas com filtros
            Page<SecurityAlert> alerts = securityAlertService.getAlertsByCriteria(
                status, severity, alertType, userId, ipAddress, startDateTime, endDateTime, pageable
            );

            logger.info("Security alerts search completed successfully: {} alerts", alerts.getTotalElements());
            return ResponseEntity.ok().body(alerts);

        } catch (Exception e) {
            logger.error("Error searching security alerts: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @PostMapping("/{alertId}/resolve")
    @Operation(summary = "Resolver alerta", description = "Marca um alerta como resolvido (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Alerta resolvido com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "404", description = "Alerta não encontrado"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<SecurityAlert> resolveAlert(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "ID do alerta") @PathVariable UUID alertId,
        @Parameter(description = "Notas de resolução") @RequestParam(required = false) String resolutionNotes) {

        logger.info("Resolve security alert request: {}", alertId);

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Resolver alerta
            String resolvedBy = (String) authResult.get("user");
            SecurityAlert resolvedAlert = securityAlertService.resolveAlert(alertId, resolvedBy, resolutionNotes);

            logger.info("Security alert resolved successfully: {} by {}", alertId, resolvedBy);
            return ResponseEntity.ok().body(resolvedAlert);

        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                logger.warn("Security alert not found: {}", alertId);
                return ResponseEntity.status(404).body(null);
            }
            logger.error("Error resolving security alert: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        } catch (Exception e) {
            logger.error("Error resolving security alert: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @PostMapping("/{alertId}/dismiss")
    @Operation(summary = "Descartar alerta", description = "Marca um alerta como descartado (falso positivo) (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Alerta descartado com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "404", description = "Alerta não encontrado"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<SecurityAlert> dismissAlert(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "ID do alerta") @PathVariable UUID alertId,
        @Parameter(description = "Motivo do descarte") @RequestParam(required = false) String dismissalReason) {

        logger.info("Dismiss security alert request: {}", alertId);

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Descartar alerta
            String dismissedBy = (String) authResult.get("user");
            SecurityAlert dismissedAlert = securityAlertService.dismissAlert(alertId, dismissedBy, dismissalReason);

            logger.info("Security alert dismissed successfully: {} by {}", alertId, dismissedBy);
            return ResponseEntity.ok().body(dismissedAlert);

        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                logger.warn("Security alert not found: {}", alertId);
                return ResponseEntity.status(404).body(null);
            }
            logger.error("Error dismissing security alert: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        } catch (Exception e) {
            logger.error("Error dismissing security alert: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @PostMapping("/{alertId}/escalate")
    @Operation(summary = "Escalar alerta", description = "Escala um alerta para nível superior (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Alerta escalado com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "404", description = "Alerta não encontrado"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<SecurityAlert> escalateAlert(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "ID do alerta") @PathVariable UUID alertId,
        @Parameter(description = "Motivo da escalação") @RequestParam(required = false) String escalationReason) {

        logger.info("Escalate security alert request: {}", alertId);

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Escalar alerta
            String escalatedBy = (String) authResult.get("user");
            SecurityAlert escalatedAlert = securityAlertService.escalateAlert(alertId, escalatedBy, escalationReason);

            logger.info("Security alert escalated successfully: {} by {}", alertId, escalatedBy);
            return ResponseEntity.ok().body(escalatedAlert);

        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                logger.warn("Security alert not found: {}", alertId);
                return ResponseEntity.status(404).body(null);
            }
            logger.error("Error escalating security alert: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        } catch (Exception e) {
            logger.error("Error escalating security alert: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/statistics")
    @Operation(summary = "Estatísticas de alertas", description = "Retorna estatísticas dos alertas de segurança (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Estatísticas retornadas com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<Map<String, Object>> getAlertStatistics(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Security alerts statistics request");

        try {
            // Verificar autenticação e autorização
            Map<String, Object> authResult = authService.validateTokenAndGetUser(token);
            boolean authenticated = (Boolean) authResult.get("authenticated");

            if (!authenticated) {
                return ResponseEntity.status(401).body(null);
            }

            // Verificar se é ADMIN
            String role = (String) authResult.get("role");
            if (!"ADMIN".equals(role)) {
                return ResponseEntity.status(403).body(null);
            }

            // Obter estatísticas
            Map<String, Object> statistics = securityAlertService.getAlertStatistics();

            logger.info("Security alerts statistics retrieved successfully");
            return ResponseEntity.ok().body(statistics);

        } catch (Exception e) {
            logger.error("Error retrieving security alerts statistics: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }
}
