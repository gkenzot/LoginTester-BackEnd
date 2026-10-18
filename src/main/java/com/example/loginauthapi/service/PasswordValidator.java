package com.example.loginauthapi.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Valida força da senha conforme política do sistema.
 * Reutilizado em registro e em alteração de senha.
 * Lista de senhas fracas: app.password.common-passwords (vírgula) ou
 * app.password.common-passwords-file (uma senha por linha); se o arquivo estiver definido, tem prioridade.
 */
@Component
public class PasswordValidator {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 128;
    private static final Set<String> DEFAULT_COMMON_PASSWORDS = Set.of(
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "1234567890", "qwerty", "abc123", "password123"
    );

    private final Set<String> commonPasswords;

    public PasswordValidator(
            ResourceLoader resourceLoader,
            @Value("${app.password.common-passwords:}") String commonPasswordsConfig,
            @Value("${app.password.common-passwords-file:}") String commonPasswordsFilePath) {
        Set<String> loaded = loadCommonPasswords(resourceLoader, commonPasswordsFilePath, commonPasswordsConfig);
        this.commonPasswords = loaded.isEmpty() ? DEFAULT_COMMON_PASSWORDS : loaded;
    }

    private static Set<String> loadCommonPasswords(ResourceLoader resourceLoader, String filePath, String propertyList) {
        if (filePath != null && !filePath.trim().isEmpty()) {
            try {
                Resource resource = resourceLoader.getResource(filePath.startsWith("file:") ? filePath : "file:" + filePath);
                if (resource.exists() && resource.isReadable()) {
                    Set<String> fromFile = new HashSet<>();
                    try (var reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            String trimmed = line.trim();
                            if (!trimmed.isEmpty()) {
                                fromFile.add(trimmed);
                            }
                        }
                    }
                    if (!fromFile.isEmpty()) {
                        return fromFile;
                    }
                }
            } catch (Exception ignored) {
                // fall through to property or default
            }
        }
        if (propertyList != null && !propertyList.trim().isEmpty()) {
            return Arrays.stream(propertyList.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
        }
        return Set.of();
    }

    /**
     * Valida a senha e lança ResponseStatusException (BAD_REQUEST) se não atender aos critérios.
     */
    public void validate(String password) {
        List<String> errors = new ArrayList<>();

        if (password == null || password.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Senha é obrigatória");
        }

        if (password.length() < MIN_LENGTH) {
            errors.add("Senha deve ter pelo menos " + MIN_LENGTH + " caracteres");
        }

        if (password.length() > MAX_LENGTH) {
            errors.add("Senha deve ter no máximo " + MAX_LENGTH + " caracteres");
        }

        if (!password.matches(".*[a-z].*")) {
            errors.add("Senha deve conter pelo menos uma letra minúscula");
        }

        if (!password.matches(".*[A-Z].*")) {
            errors.add("Senha deve conter pelo menos uma letra maiúscula");
        }

        if (!password.matches(".*\\d.*")) {
            errors.add("Senha deve conter pelo menos um número");
        }

        if (!password.matches(".*[@$!%*?&].*")) {
            errors.add("Senha deve conter pelo menos um símbolo especial (@$!%*?&)");
        }

        if (password.trim().isEmpty()) {
            errors.add("Senha não pode conter apenas espaços");
        }

        String lower = password.toLowerCase();
        for (String common : commonPasswords) {
            if (lower.contains(common.toLowerCase())) {
                errors.add("Senha muito comum. Escolha uma senha mais segura");
                break;
            }
        }

        if (!errors.isEmpty()) {
            String message = "Senha não atende aos critérios de segurança: " + String.join(", ", errors);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
        }
    }
}
