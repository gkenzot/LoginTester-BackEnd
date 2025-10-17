package com.example.loginauthapi.controller;

import com.example.loginauthapi.domain.AuditEvent;
import com.example.loginauthapi.service.AuditService;
import com.example.loginauthapi.service.AuthService;
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

/**
 * Controller para gerenciar logs de auditoria
 * 
 * Fornece endpoints para consultar eventos de auditoria (apenas para ADMIN)
 */
@RestController
@RequestMapping("/api/audit")
@Tag(name = "Auditoria", description = "Endpoints para consulta de logs de auditoria")
@RequiredArgsConstructor
public class AuditController {

    private static final Logger logger = LoggerFactory.getLogger(AuditController.class);

    private final AuditService auditService;
    private final AuthService authService;

    @GetMapping("/logs")
    @Operation(summary = "Listar logs de auditoria", description = "Retorna logs de auditoria com paginação (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Logs retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<Page<AuditEvent>> getAuditLogs(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "Número da página (0-based)") @RequestParam(defaultValue = "0") int page,
        @Parameter(description = "Tamanho da página") @RequestParam(defaultValue = "20") int size,
        @Parameter(description = "Campo para ordenação") @RequestParam(defaultValue = "timestamp") String sortBy,
        @Parameter(description = "Direção da ordenação (asc/desc)") @RequestParam(defaultValue = "desc") String sortDir,
        @Parameter(description = "Filtrar por usuário") @RequestParam(required = false) String userId,
        @Parameter(description = "Filtrar por tipo de evento") @RequestParam(required = false) String eventType,
        @Parameter(description = "Filtrar por resultado") @RequestParam(required = false) AuditEvent.AuditResult result,
        @Parameter(description = "Filtrar por IP") @RequestParam(required = false) String ipAddress,
        @Parameter(description = "Data início (yyyy-MM-dd HH:mm:ss)") @RequestParam(required = false) String startDate,
        @Parameter(description = "Data fim (yyyy-MM-dd HH:mm:ss)") @RequestParam(required = false) String endDate) {

        logger.info("Audit logs request");

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
            Sort sort = Sort.by(Sort.Direction.fromString(sortDir), sortBy);
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

            // Buscar logs com filtros
            Page<AuditEvent> auditLogs = auditService.getEventsByCriteria(
                userId, eventType, result, ipAddress, startDateTime, endDateTime, pageable
            );

            logger.info("Audit logs retrieved successfully: {} events", auditLogs.getTotalElements());
            return ResponseEntity.ok().body(auditLogs);

        } catch (Exception e) {
            logger.error("Error retrieving audit logs: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/security-events")
    @Operation(summary = "Eventos de segurança", description = "Retorna eventos suspeitos e de segurança (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Eventos retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<AuditEvent>> getSecurityEvents(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "Número de dias para buscar") @RequestParam(defaultValue = "7") int days) {

        logger.info("Security events request for last {} days", days);

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

            // Buscar eventos suspeitos do período
            LocalDateTime startDate = LocalDateTime.now().minusDays(days);
            LocalDateTime endDate = LocalDateTime.now();
            
            List<AuditEvent> securityEvents = auditService.getSuspiciousEventsByPeriod(startDate, endDate);

            logger.info("Security events retrieved successfully: {} events", securityEvents.size());
            return ResponseEntity.ok().body(securityEvents);

        } catch (Exception e) {
            logger.error("Error retrieving security events: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/user/{userId}/activity")
    @Operation(summary = "Atividade do usuário", description = "Retorna atividade de auditoria de um usuário específico (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Atividade retornada com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<AuditEvent>> getUserActivity(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "ID do usuário") @PathVariable String userId,
        @Parameter(description = "Número de dias para buscar") @RequestParam(defaultValue = "30") int days) {

        logger.info("User activity request for user: {} (last {} days)", userId, days);

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

            // Buscar atividade do usuário do período
            LocalDateTime startDate = LocalDateTime.now().minusDays(days);
            LocalDateTime endDate = LocalDateTime.now();
            
            List<AuditEvent> userActivity = auditService.getAuditLogsByPeriod(startDate, endDate)
                .stream()
                .filter(event -> userId.equals(event.getUserId()))
                .toList();

            logger.info("User activity retrieved successfully: {} events for user {}", userActivity.size(), userId);
            return ResponseEntity.ok().body(userActivity);

        } catch (Exception e) {
            logger.error("Error retrieving user activity: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/login-events")
    @Operation(summary = "Eventos de login", description = "Retorna eventos de login e logout (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Eventos de login retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<AuditEvent>> getLoginEvents(
        @CookieValue(name = "jwt", required = false) String token,
        @Parameter(description = "Número de dias para buscar") @RequestParam(defaultValue = "7") int days) {

        logger.info("Login events request for last {} days", days);

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

            // Buscar eventos de login do período
            LocalDateTime startDate = LocalDateTime.now().minusDays(days);
            LocalDateTime endDate = LocalDateTime.now();
            
            List<AuditEvent> loginEvents = auditService.getLoginEventsByPeriod(startDate, endDate);

            logger.info("Login events retrieved successfully: {} events", loginEvents.size());
            return ResponseEntity.ok().body(loginEvents);

        } catch (Exception e) {
            logger.error("Error retrieving login events: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/recent")
    @Operation(summary = "Eventos recentes", description = "Retorna eventos de auditoria recentes (últimas 24h) (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Eventos recentes retornados com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<List<AuditEvent>> getRecentEvents(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Recent events request");

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

            // Buscar eventos recentes
            List<AuditEvent> recentEvents = auditService.getRecentEvents();

            logger.info("Recent events retrieved successfully: {} events", recentEvents.size());
            return ResponseEntity.ok().body(recentEvents);

        } catch (Exception e) {
            logger.error("Error retrieving recent events: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @GetMapping("/statistics")
    @Operation(summary = "Estatísticas de auditoria", description = "Retorna estatísticas dos eventos de auditoria (apenas ADMIN)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Estatísticas retornadas com sucesso"),
        @ApiResponse(responseCode = "401", description = "Não autenticado"),
        @ApiResponse(responseCode = "403", description = "Acesso negado - apenas ADMIN"),
        @ApiResponse(responseCode = "429", description = "Rate limit excedido")
    })
    public ResponseEntity<Map<String, Object>> getAuditStatistics(
        @CookieValue(name = "jwt", required = false) String token) {

        logger.info("Audit statistics request");

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
            Map<String, Object> statistics = auditService.getAuditStatistics();

            logger.info("Audit statistics retrieved successfully");
            return ResponseEntity.ok().body(statistics);

        } catch (Exception e) {
            logger.error("Error retrieving audit statistics: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }
}
