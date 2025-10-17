package com.example.loginauthapi.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotação para marcar métodos que devem ser auditados
 * 
 * Usada em conjunto com AuditAspect para interceptação automática de eventos
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Auditable {
    
    /**
     * Tipo do evento de auditoria
     */
    String eventType() default "";
    
    /**
     * Descrição do evento
     */
    String description() default "";
    
    /**
     * Se deve registrar apenas em caso de sucesso
     */
    boolean successOnly() default false;
    
    /**
     * Se deve registrar apenas em caso de falha
     */
    boolean failureOnly() default false;
    
    /**
     * Se deve incluir parâmetros do método nos metadados
     */
    boolean includeParameters() default true;
    
    /**
     * Se deve incluir resultado do método nos metadados
     */
    boolean includeResult() default true;
}
