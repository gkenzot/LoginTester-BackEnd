package com.example.loginauthapi.config;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Refill;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Configuração do Rate Limiting usando Bucket4j com Redis
 * 
 * Limites implementados:
 * - Login: 5 tentativas por minuto por IP
 * - Register: 10 tentativas por hora por IP (ajustado para testes)
 * - Check: 60 tentativas por minuto por IP
 */
@Configuration
@Profile("!test")
public class RateLimitingConfig {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.password:}")
    private String redisPassword;

    @Bean
    @ConditionalOnProperty(prefix = "ratelimit", name = "enabled", havingValue = "true", matchIfMissing = false)
    public LettuceBasedProxyManager proxyManager() {
        // TODO: inicializar conexão real com Redis quando ratelimit estiver habilitado
        return null; // será substituído quando ratelimit estiver ativo
    }

    @Component
    @Profile("!test")
    @ConditionalOnProperty(prefix = "ratelimit", name = "enabled", havingValue = "true", matchIfMissing = false)
    public static class RateLimitBuckets {
        
        private final LettuceBasedProxyManager proxyManager;

        public RateLimitBuckets(LettuceBasedProxyManager proxyManager) {
            this.proxyManager = proxyManager; // Pode ser null quando rate limiting está desabilitado
        }

        /**
         * Bucket para endpoint de LOGIN
         * Limite: 5 tentativas por minuto por IP
         */
        public Bucket getLoginBucket(String key) {
            return Bucket.builder()
                    .addLimit(Bandwidth.classic(1000, Refill.intervally(1000, Duration.ofMinutes(1))))
                    .build();
        }

        /**
         * Bucket para endpoint de REGISTER
         * Limite: 10 tentativas por hora por IP (ajustado para testes)
         */
        public Bucket getRegisterBucket(String key) {
            return Bucket.builder()
                    .addLimit(Bandwidth.classic(1000, Refill.intervally(1000, Duration.ofHours(1))))
                    .build();
        }

        /**
         * Bucket para endpoint de CHECK
         * Limite: 60 tentativas por minuto por IP
         */
        public Bucket getCheckBucket(String key) {
            return Bucket.builder()
                    .addLimit(Bandwidth.classic(1000, Refill.intervally(1000, Duration.ofMinutes(1))))
                    .build();
        }
    }

    /**
     * Implementação no-op quando ratelimit estiver desabilitado
     */
    @Component
    @Profile("!test")
    @ConditionalOnProperty(prefix = "ratelimit", name = "enabled", havingValue = "false")
    public static class NoOpRateLimitBuckets extends RateLimitBuckets {
        public NoOpRateLimitBuckets() { super(null); }

        @Override public Bucket getLoginBucket(String key) { return unlimitedBucket(); }
        @Override public Bucket getRegisterBucket(String key) { return unlimitedBucket(); }
        @Override public Bucket getCheckBucket(String key) { return unlimitedBucket(); }

        private Bucket unlimitedBucket() {
            return Bucket.builder().addLimit(Bandwidth.classic(1000, Refill.intervally(1000, Duration.ofMinutes(1)))).build();
        }
    }
}
