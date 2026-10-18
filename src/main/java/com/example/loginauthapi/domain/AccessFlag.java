package com.example.loginauthapi.domain;

import java.util.Map;
import java.util.Set;

/**
 * Códigos de flags de acesso (páginas/funcionalidades).
 * Usa nomes em vez de números; o id numérico fica oculto no catálogo do banco.
 * USER só acessa rotas/endpoints cuja flag esteja na sua lista; ADMIN ignora.
 */
public final class AccessFlag {

    private AccessFlag() {}

    /** Administrar usuários e suas flags (gestão de usuários + atribuição de flags). */
    public static final String USER_MANAGE = "USER_MANAGE";

    /** Alias usado no AdminController e validação (mesmo código que USER_MANAGE). */
    public static final String MANAGE_USERS_AND_FLAGS = USER_MANAGE;

    /** Todas as flags que possuem página atualmente (para validação/lista). */
    public static final Set<String> ALL = Set.of(USER_MANAGE);

    /** Descrição de cada flag (code -> descrição). */
    public static final Map<String, String> DESCRIPTIONS = Map.of(
        USER_MANAGE, "Administrar usuários e suas flags"
    );
}
