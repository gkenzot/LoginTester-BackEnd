package com.example.loginauthapi.util;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Gera hashes BCrypt para dev-data.sql (mesmo encoder do Spring: BCryptPasswordEncoder).
 * Executar: mvn test -Dtest=DevDataBcryptGenerator#generateHashes
 * Copiar a saída para LoginTester-DB/dev-data.sql.
 */
class DevDataBcryptGenerator {

    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    @Test
    void generateHashes() {
        String[] passwords = { "admin123", "user123", "unverified123", "kenzo123" };
        for (String p : passwords) {
            System.out.println(ENCODER.encode(p));
        }
    }
}
