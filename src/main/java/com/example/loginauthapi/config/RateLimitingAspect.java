package com.example.loginauthapi.config;

import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.context.annotation.Profile;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;

/**
 * Aspect para aplicar Rate Limiting usando Bucket4j
 */
@Aspect
@Component
@Profile("!test")
@ConditionalOnProperty(prefix = "ratelimit", name = "enabled", havingValue = "true", matchIfMissing = false)
public class RateLimitingAspect {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingAspect.class);

    @Autowired
    private RateLimitingConfig.RateLimitBuckets rateLimitBuckets;

    @Around("@annotation(rateLimit)")
    public Object applyRateLimit(ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable {
        
        // Obter IP do cliente
        String clientIp = getClientIpAddress();
        
        // Obter bucket apropriado baseado no tipo de endpoint
        Bucket bucket = getBucketForEndpoint(rateLimit.value(), clientIp);
        
        // Verificar se há tokens disponíveis
        if (bucket.tryConsume(1)) {
            logger.debug("Rate limit OK para IP: {} no endpoint: {}", clientIp, rateLimit.value());
            return joinPoint.proceed();
        } else {
            logger.warn("Rate limit EXCEDIDO para IP: {} no endpoint: {}", clientIp, rateLimit.value());
            return createRateLimitExceededResponse(rateLimit.value());
        }
    }

    /**
     * Obtém o IP real do cliente considerando proxies
     */
    private String getClientIpAddress() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return "unknown";
        }
        
        HttpServletRequest request = attributes.getRequest();
        
        // Verificar headers de proxy primeiro
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        // Fallback para IP remoto
        return request.getRemoteAddr();
    }

    /**
     * Obtém o bucket apropriado baseado no tipo de endpoint
     */
    private Bucket getBucketForEndpoint(RateLimit.EndpointType endpointType, String clientIp) {
        String key = endpointType.name().toLowerCase() + ":" + clientIp;
        
        return switch (endpointType) {
            case LOGIN -> rateLimitBuckets.getLoginBucket(key);
            case REGISTER -> rateLimitBuckets.getRegisterBucket(key);
            case CHECK -> rateLimitBuckets.getCheckBucket(key);
        };
    }

    /**
     * Cria resposta de erro quando rate limit é excedido
     */
    private ResponseEntity<Map<String, Object>> createRateLimitExceededResponse(RateLimit.EndpointType endpointType) {
        String message = switch (endpointType) {
            case LOGIN -> "Muitas tentativas de login. Tente novamente em 1 minuto.";
            case REGISTER -> "Muitas tentativas de registro. Tente novamente em 1 hora.";
            case CHECK -> "Muitas verificações de token. Tente novamente em 1 minuto.";
        };
        
        Map<String, Object> errorResponse = Map.of(
            "error", "Rate Limit Exceeded",
            "message", message,
            "timestamp", System.currentTimeMillis()
        );
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
    }
}
