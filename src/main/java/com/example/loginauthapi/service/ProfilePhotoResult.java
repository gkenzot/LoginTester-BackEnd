package com.example.loginauthapi.service;

import org.springframework.core.io.Resource;

/**
 * Resultado da leitura da foto de perfil em uma única consulta (evita N+1).
 */
public record ProfilePhotoResult(Resource resource, String contentType) {}
