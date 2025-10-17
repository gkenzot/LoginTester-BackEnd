/**
 * @fileoverview Serviço de blacklist de tokens JWT
 * @description Gerencia blacklist de tokens usando Redis para invalidar tokens comprometidos
 */

package com.example.loginauthapi.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Set;

/**
 * Serviço para gerenciar blacklist de tokens JWT
 * 
 * Funcionalidades:
 * - Adicionar tokens à blacklist
 * - Verificar se token está na blacklist
 * - Remover tokens da blacklist
 * - Limpar blacklist expirada
 * - Estatísticas da blacklist
 */
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenBlacklistService.class);
    
    // Prefixo para chaves Redis da blacklist
    private static final String BLACKLIST_PREFIX = "blacklist:token:";
    private static final String BLACKLIST_USER_PREFIX = "blacklist:user:";
    private static final String BLACKLIST_STATS_KEY = "blacklist:stats";
    
    // TTL padrão para tokens na blacklist (7 dias)
    private static final Duration DEFAULT_TTL = Duration.ofDays(7);
    
    private final RedisTemplate<String, String> redisTemplate;
    
    /**
     * Adiciona um token à blacklist
     * 
     * @param token - Token JWT a ser blacklisted
     * @param userId - ID do usuário (opcional, para estatísticas)
     * @param reason - Motivo da blacklist (opcional)
     */
    public void blacklistToken(String token, String userId, String reason) {
        try {
            String tokenKey = BLACKLIST_PREFIX + token;
            String userKey = BLACKLIST_USER_PREFIX + userId;
            
            // Armazenar token na blacklist com TTL
            redisTemplate.opsForValue().set(
                tokenKey, 
                reason != null ? reason : "blacklisted", 
                DEFAULT_TTL
            );
            
            // Armazenar referência por usuário (para estatísticas)
            if (userId != null) {
                redisTemplate.opsForSet().add(userKey, token);
                redisTemplate.expire(userKey, DEFAULT_TTL);
            }
            
            // Atualizar estatísticas
            updateStats("tokens_blacklisted", 1);
            
            logger.info("Token blacklisted successfully. User: {}, Reason: {}", userId, reason);
            
        } catch (Exception e) {
            logger.error("Error blacklisting token: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to blacklist token", e);
        }
    }
    
    /**
     * Adiciona um token à blacklist (versão simplificada)
     * 
     * @param token - Token JWT a ser blacklisted
     */
    public void blacklistToken(String token) {
        blacklistToken(token, null, null);
    }
    
    /**
     * Verifica se um token está na blacklist
     * 
     * @param token - Token JWT a ser verificado
     * @return true se o token está na blacklist, false caso contrário
     */
    public boolean isTokenBlacklisted(String token) {
        try {
            String tokenKey = BLACKLIST_PREFIX + token;
            Boolean exists = redisTemplate.hasKey(tokenKey);
            
            if (Boolean.TRUE.equals(exists)) {
                logger.debug("Token found in blacklist: {}", token.substring(0, Math.min(20, token.length())) + "...");
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Error checking token blacklist: {}", e.getMessage(), e);
            // Em caso de erro, assumir que não está blacklisted para não bloquear usuários legítimos
            return false;
        }
    }
    
    /**
     * Remove um token da blacklist
     * 
     * @param token - Token JWT a ser removido da blacklist
     */
    public void removeFromBlacklist(String token) {
        try {
            String tokenKey = BLACKLIST_PREFIX + token;
            Boolean deleted = redisTemplate.delete(tokenKey);
            
            if (Boolean.TRUE.equals(deleted)) {
                logger.info("Token removed from blacklist successfully");
                updateStats("tokens_removed", 1);
            }
            
        } catch (Exception e) {
            logger.error("Error removing token from blacklist: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Blacklista todos os tokens de um usuário (logout global)
     * 
     * @param userId - ID do usuário
     * @param reason - Motivo da blacklist
     */
    public void blacklistAllUserTokens(String userId, String reason) {
        try {
            String userKey = BLACKLIST_USER_PREFIX + userId;
            Set<String> userTokens = redisTemplate.opsForSet().members(userKey);
            
            if (userTokens != null && !userTokens.isEmpty()) {
                for (String token : userTokens) {
                    blacklistToken(token, userId, reason);
                }
                logger.info("All tokens blacklisted for user: {}, Count: {}", userId, userTokens.size());
            }
            
        } catch (Exception e) {
            logger.error("Error blacklisting all user tokens: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Obtém estatísticas da blacklist
     * 
     * @return Estatísticas da blacklist
     */
    public BlacklistStats getBlacklistStats() {
        try {
            String statsKey = BLACKLIST_STATS_KEY;
            String tokensBlacklisted = redisTemplate.opsForValue().get(statsKey + ":tokens_blacklisted");
            String tokensRemoved = redisTemplate.opsForValue().get(statsKey + ":tokens_removed");
            
            return new BlacklistStats(
                tokensBlacklisted != null ? Long.parseLong(tokensBlacklisted) : 0L,
                tokensRemoved != null ? Long.parseLong(tokensRemoved) : 0L
            );
            
        } catch (Exception e) {
            logger.error("Error getting blacklist stats: {}", e.getMessage(), e);
            return new BlacklistStats(0L, 0L);
        }
    }
    
    /**
     * Limpa tokens expirados da blacklist
     * 
     * @return Número de tokens removidos
     */
    public long cleanupExpiredTokens() {
        try {
            // Redis automaticamente remove chaves expiradas
            // Este método pode ser usado para limpeza manual se necessário
            logger.info("Cleanup completed - Redis handles TTL automatically");
            return 0L;
            
        } catch (Exception e) {
            logger.error("Error during cleanup: {}", e.getMessage(), e);
            return 0L;
        }
    }
    
    /**
     * Atualiza estatísticas da blacklist
     * 
     * @param statName - Nome da estatística
     * @param increment - Valor a incrementar
     */
    private void updateStats(String statName, long increment) {
        try {
            String statsKey = BLACKLIST_STATS_KEY + ":" + statName;
            redisTemplate.opsForValue().increment(statsKey, increment);
            redisTemplate.expire(statsKey, Duration.ofDays(30)); // Manter stats por 30 dias
            
        } catch (Exception e) {
            logger.debug("Error updating stats: {}", e.getMessage());
            // Não falhar por erro de estatísticas
        }
    }
    
    /**
     * Classe para estatísticas da blacklist
     */
    public static class BlacklistStats {
        private final long tokensBlacklisted;
        private final long tokensRemoved;
        
        public BlacklistStats(long tokensBlacklisted, long tokensRemoved) {
            this.tokensBlacklisted = tokensBlacklisted;
            this.tokensRemoved = tokensRemoved;
        }
        
        public long getTokensBlacklisted() {
            return tokensBlacklisted;
        }
        
        public long getTokensRemoved() {
            return tokensRemoved;
        }
        
        public long getActiveBlacklistedTokens() {
            return tokensBlacklisted - tokensRemoved;
        }
        
        @Override
        public String toString() {
            return String.format("BlacklistStats{tokensBlacklisted=%d, tokensRemoved=%d, active=%d}", 
                tokensBlacklisted, tokensRemoved, getActiveBlacklistedTokens());
        }
    }
}
