package com.example.loginauthapi.aspect;

import com.example.loginauthapi.annotation.Auditable;
import com.example.loginauthapi.domain.AuditEvent;
import com.example.loginauthapi.service.AuditService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Aspecto para interceptação automática de métodos anotados com @Auditable
 * 
 * Registra automaticamente eventos de auditoria para métodos marcados
 */
@Aspect
@Component
public class AuditAspect {

    private static final Logger logger = LoggerFactory.getLogger(AuditAspect.class);

    @Autowired
    private AuditService auditService;

    @Around("@annotation(auditable)")
    public Object auditMethod(ProceedingJoinPoint joinPoint, Auditable auditable) throws Throwable {
        long startTime = System.currentTimeMillis();
        String userId = null;
        String ipAddress = null;
        String userAgent = null;
        boolean success = false;
        Object result = null;

        try {
            // Obter informações da requisição HTTP
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                ipAddress = getClientIpAddress(request);
                userAgent = request.getHeader("User-Agent");
            }

            // Tentar obter userId do contexto de segurança ou parâmetros
            userId = extractUserId(joinPoint);

            // Executar o método original
            result = joinPoint.proceed();
            success = true;

            // Registrar evento de sucesso se configurado
            if (!auditable.failureOnly()) {
                logAuditEvent(auditable, userId, ipAddress, userAgent, success, result, null, joinPoint, startTime);
            }

            return result;

        } catch (Exception e) {
            success = false;

            // Registrar evento de falha se configurado
            if (!auditable.successOnly()) {
                logAuditEvent(auditable, userId, ipAddress, userAgent, success, null, e, joinPoint, startTime);
            }

            throw e;
        }
    }

    /**
     * Registra evento de auditoria
     */
    private void logAuditEvent(Auditable auditable, String userId, String ipAddress, String userAgent,
                             boolean success, Object result, Exception exception, ProceedingJoinPoint joinPoint,
                             long startTime) {
        try {
            String eventType = auditable.eventType();
            if (eventType.isEmpty()) {
                eventType = generateEventType(joinPoint, success);
            }

            String description = auditable.description();
            if (description.isEmpty()) {
                description = generateDescription(joinPoint, success, exception);
            }

            AuditEvent.AuditResult auditResult = success ? AuditEvent.AuditResult.SUCCESS : AuditEvent.AuditResult.FAILURE;
            if (exception != null && isSuspiciousException(exception)) {
                auditResult = AuditEvent.AuditResult.SUSPICIOUS;
            }

            Map<String, Object> metadata = buildMetadata(joinPoint, result, exception, startTime, auditable);

            auditService.logEvent(userId, eventType, description, ipAddress, userAgent, auditResult, metadata);

        } catch (Exception e) {
            logger.error("Error logging audit event: {}", e.getMessage(), e);
        }
    }

    /**
     * Gera tipo de evento baseado no método e resultado
     */
    private String generateEventType(ProceedingJoinPoint joinPoint, boolean success) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String methodName = signature.getMethod().getName();
        String className = signature.getMethod().getDeclaringClass().getSimpleName();

        if (methodName.contains("login")) {
            return success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE";
        } else if (methodName.contains("logout")) {
            return "LOGOUT";
        } else if (methodName.contains("register")) {
            return success ? "USER_REGISTRATION_SUCCESS" : "USER_REGISTRATION_FAILURE";
        } else if (methodName.contains("refresh")) {
            return success ? "TOKEN_REFRESH_SUCCESS" : "TOKEN_REFRESH_FAILURE";
        } else if (methodName.contains("password")) {
            return "PASSWORD_CHANGE";
        } else {
            return className.toUpperCase() + "_" + methodName.toUpperCase();
        }
    }

    /**
     * Gera descrição do evento
     */
    private String generateDescription(ProceedingJoinPoint joinPoint, boolean success, Exception exception) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String methodName = signature.getMethod().getName();
        String className = signature.getMethod().getDeclaringClass().getSimpleName();

        if (success) {
            return String.format("Método %s.%s executado com sucesso", className, methodName);
        } else {
            return String.format("Falha na execução do método %s.%s: %s", className, methodName, 
                exception != null ? exception.getMessage() : "Erro desconhecido");
        }
    }

    /**
     * Constrói metadados do evento
     */
    private Map<String, Object> buildMetadata(ProceedingJoinPoint joinPoint, Object result, Exception exception,
                                            long startTime, Auditable auditable) {
        Map<String, Object> metadata = new HashMap<>();

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        metadata.put("className", signature.getMethod().getDeclaringClass().getSimpleName());
        metadata.put("methodName", signature.getMethod().getName());
        metadata.put("executionTime", System.currentTimeMillis() - startTime);
        metadata.put("timestamp", LocalDateTime.now());

        if (auditable.includeParameters()) {
            Object[] args = joinPoint.getArgs();
            Map<String, Object> parameters = new HashMap<>();
            String[] paramNames = signature.getParameterNames();
            
            for (int i = 0; i < args.length; i++) {
                String paramName = i < paramNames.length ? paramNames[i] : "arg" + i;
                Object arg = args[i];
                
                // Não incluir dados sensíveis
                if (isSensitiveParameter(paramName)) {
                    parameters.put(paramName, "[REDACTED]");
                } else {
                    parameters.put(paramName, arg != null ? arg.toString() : null);
                }
            }
            metadata.put("parameters", parameters);
        }

        if (auditable.includeResult() && result != null) {
            metadata.put("result", result.toString());
        }

        if (exception != null) {
            metadata.put("exception", exception.getClass().getSimpleName());
            metadata.put("exceptionMessage", exception.getMessage());
        }

        return metadata;
    }

    /**
     * Extrai userId do contexto ou parâmetros
     */
    private String extractUserId(ProceedingJoinPoint joinPoint) {
        try {
            // Tentar obter do contexto de segurança
            org.springframework.security.core.Authentication auth = 
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
                return auth.getName();
            }

            // Tentar obter dos parâmetros do método
            Object[] args = joinPoint.getArgs();
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            String[] paramNames = signature.getParameterNames();

            for (int i = 0; i < args.length; i++) {
                String paramName = i < paramNames.length ? paramNames[i] : "";
                Object arg = args[i];
                
                if ("email".equals(paramName) && arg instanceof String) {
                    return (String) arg;
                } else if ("userId".equals(paramName) && arg instanceof String) {
                    return (String) arg;
                }
            }

        } catch (Exception e) {
            logger.debug("Could not extract userId: {}", e.getMessage());
        }

        return "unknown";
    }

    /**
     * Obtém IP real do cliente
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    /**
     * Verifica se é uma exceção suspeita
     */
    private boolean isSuspiciousException(Exception exception) {
        String message = exception.getMessage();
        if (message == null) return false;

        String lowerMessage = message.toLowerCase();
        return lowerMessage.contains("suspicious") ||
               lowerMessage.contains("attack") ||
               lowerMessage.contains("injection") ||
               lowerMessage.contains("unauthorized") ||
               lowerMessage.contains("forbidden");
    }

    /**
     * Verifica se é um parâmetro sensível
     */
    private boolean isSensitiveParameter(String paramName) {
        String lowerParamName = paramName.toLowerCase();
        return lowerParamName.contains("password") ||
               lowerParamName.contains("token") ||
               lowerParamName.contains("secret") ||
               lowerParamName.contains("key");
    }
}
