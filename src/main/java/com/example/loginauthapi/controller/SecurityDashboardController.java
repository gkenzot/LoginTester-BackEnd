package com.example.loginauthapi.controller;

import com.example.loginauthapi.domain.AuditEvent;
import com.example.loginauthapi.dto.SecurityMetricsDTO;
import com.example.loginauthapi.service.AuthService;
import com.example.loginauthapi.service.SecurityMonitoringService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Controller para dashboard de segurança
 * 
 * Fornece endpoints para métricas e monitoramento de segurança (apenas ADMIN)
 */
@RestController
@RequestMapping("/api/security")
@Tag(name = "Monitoramento de Segurança", description = "Endpoints para dashboard de segurança")
@RequiredArgsConstructor
public class SecurityDashboardController {

    private static final Logger logger = LoggerFactory.getLogger(SecurityDashboardController.class);

    private final SecurityMonitoringService securityMonitoringService;
    private final AuthService authService;

    @GetMapping("/dashboard")
    @Operation(summary = "Dashboard de segurança", description = "Retorna métricas completas de segurança (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Métricas retornadas com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<SecurityMetricsDTO> getDashboard(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Security dashboard request");

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

            // Obter métricas de segurança
            SecurityMetricsDTO metrics = securityMonitoringService.getSecurityMetrics();

            logger.info("Security dashboard data retrieved successfully");
            return ResponseEntity.ok().body(metrics);

        } catch (Exception e) {
            logger.error("Error retrieving security dashboard: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/metrics")
    @Operation(summary = "Métricas de segurança", description = "Retorna métricas detalhadas de segurança (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Métricas retornadas com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<Map<String, Object>> getMetrics(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "Número de dias para análise") @RequestParam(defaultValue = "7") int days) {

        logger.info("Security metrics request for last {} days", days);

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

            // Obter estatísticas do período
            LocalDateTime startDate = LocalDateTime.now().minusDays(days);
            LocalDateTime endDate = LocalDateTime.now();
            
            Map<String, Object> metrics = securityMonitoringService.getSecurityStatistics(startDate, endDate);

            logger.info("Security metrics retrieved successfully");
            return ResponseEntity.ok().body(metrics);

        } catch (Exception e) {
            logger.error("Error retrieving security metrics: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/events/recent")
    @Operation(summary = "Eventos recentes", description = "Retorna eventos de segurança recentes (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Eventos retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<AuditEvent>> getRecentEvents(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "Número de horas para buscar") @RequestParam(defaultValue = "24") int hours) {

        logger.info("Recent security events request for last {} hours", hours);

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

            // Obter eventos recentes
            List<AuditEvent> recentEvents = securityMonitoringService.getRecentSecurityEvents(hours);

            logger.info("Recent security events retrieved successfully: {} events", recentEvents.size());
            return ResponseEntity.ok().body(recentEvents);

        } catch (Exception e) {
            logger.error("Error retrieving recent security events: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/login-attempts/hourly")
    @Operation(summary = "Tentativas de login por hora", description = "Retorna tentativas de login agrupadas por hora (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Dados retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<Map<String, Long>> getLoginAttemptsByHour(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Login attempts by hour request");

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

            // Obter tentativas por hora
            Map<String, Long> attemptsByHour = securityMonitoringService.getLoginAttemptsByHour();

            logger.info("Login attempts by hour retrieved successfully");
            return ResponseEntity.ok().body(attemptsByHour);

        } catch (Exception e) {
            logger.error("Error retrieving login attempts by hour: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/failed-logins/ip")
    @Operation(summary = "Logins falhados por IP", description = "Retorna logins falhados agrupados por IP (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Dados retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<Map<String, Long>> getFailedLoginsByIP(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Failed logins by IP request");

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

            // Obter falhas por IP
            Map<String, Long> failedLoginsByIP = securityMonitoringService.getFailedLoginsByIP();

            logger.info("Failed logins by IP retrieved successfully");
            return ResponseEntity.ok().body(failedLoginsByIP);

        } catch (Exception e) {
            logger.error("Error retrieving failed logins by IP: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/suspicious-activities")
    @Operation(summary = "Atividades suspeitas", description = "Retorna atividades suspeitas detectadas (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Atividades retornadas com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<com.example.loginauthapi.dto.SuspiciousActivityDTO>> getSuspiciousActivities(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Suspicious activities request");

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

            // Obter atividades suspeitas
            List<com.example.loginauthapi.dto.SuspiciousActivityDTO> suspiciousActivities = 
                securityMonitoringService.getSuspiciousActivities();

            logger.info("Suspicious activities retrieved successfully: {} activities", suspiciousActivities.size());
            return ResponseEntity.ok().body(suspiciousActivities);

        } catch (Exception e) {
            logger.error("Error retrieving suspicious activities: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/patterns")
    @Operation(summary = "Padrões suspeitos", description = "Retorna padrões suspeitos detectados (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Padrões retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<String>> getSuspiciousPatterns(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Suspicious patterns request");

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

            // Detectar padrões suspeitos
            List<String> patterns = securityMonitoringService.detectSuspiciousPatterns();

            logger.info("Suspicious patterns detected: {} patterns", patterns.size());
            return ResponseEntity.ok().body(patterns);

        } catch (Exception e) {
            logger.error("Error detecting suspicious patterns: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }
}
