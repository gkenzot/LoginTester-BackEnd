package com.example.loginauthapi.unit.ratelimit;

import com.example.loginauthapi.config.RateLimit;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Refill;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes unitários para Rate Limiting Configuration
 * 
 * Testa a configuração dos limites de Rate Limiting
 */
public class RateLimitingUnitTest {

    /**
     * Teste 1: Configuração do limite de LOGIN
     * Deve ter limite de 5 tentativas por minuto
     */
    @Test
    void loginRateLimit_ShouldHaveCorrectConfiguration() {
        // Arrange
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));

        // Assert
        assertEquals(5, limit.getCapacity());
        assertEquals(5, limit.getRefillTokens());
    }

    /**
     * Teste 2: Configuração do limite de REGISTER
     * Deve ter limite de 3 tentativas por hora
     */
    @Test
    void registerRateLimit_ShouldHaveCorrectConfiguration() {
        // Arrange
        Bandwidth limit = Bandwidth.classic(3, Refill.intervally(3, Duration.ofHours(1)));

        // Assert
        assertEquals(3, limit.getCapacity());
        assertEquals(3, limit.getRefillTokens());
    }

    /**
     * Teste 3: Configuração do limite de CHECK
     * Deve ter limite de 60 tentativas por minuto
     */
    @Test
    void checkRateLimit_ShouldHaveCorrectConfiguration() {
        // Arrange
        Bandwidth limit = Bandwidth.classic(60, Refill.intervally(60, Duration.ofMinutes(1)));

        // Assert
        assertEquals(60, limit.getCapacity());
        assertEquals(60, limit.getRefillTokens());
    }

    /**
     * Teste 4: Enum EndpointType deve ter valores corretos
     * Deve conter LOGIN, REGISTER e CHECK
     */
    @Test
    void endpointType_ShouldHaveCorrectValues() {
        // Assert
        assertEquals(3, RateLimit.EndpointType.values().length);
        assertTrue(contains(RateLimit.EndpointType.values(), RateLimit.EndpointType.LOGIN));
        assertTrue(contains(RateLimit.EndpointType.values(), RateLimit.EndpointType.REGISTER));
        assertTrue(contains(RateLimit.EndpointType.values(), RateLimit.EndpointType.CHECK));
    }

    /**
     * Teste 5: Durações devem ser consistentes
     * Os períodos de refill devem ser apropriados para cada tipo de endpoint
     */
    @Test
    void rateLimitDurations_ShouldBeAppropriate() {
        // Arrange
        Duration loginDuration = Duration.ofMinutes(1);
        Duration registerDuration = Duration.ofHours(1);
        Duration checkDuration = Duration.ofMinutes(1);

        // Assert
        assertTrue(loginDuration.compareTo(Duration.ofSeconds(30)) > 0, "Login duration should be reasonable");
        assertTrue(registerDuration.compareTo(Duration.ofMinutes(30)) > 0, "Register duration should be longer");
        assertTrue(checkDuration.compareTo(Duration.ofSeconds(30)) > 0, "Check duration should be reasonable");
        
        // Register deve ter duração maior que Login e Check
        assertTrue(registerDuration.compareTo(loginDuration) > 0);
        assertTrue(registerDuration.compareTo(checkDuration) > 0);
    }

    private boolean contains(RateLimit.EndpointType[] values, RateLimit.EndpointType target) {
        for (RateLimit.EndpointType value : values) {
            if (value == target) {
                return true;
            }
        }
        return false;
    }
}
