package com.example.loginauthapi.config;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Login Auth API")
                        .version("1.0")
                        .description("API para autenticação com JWT via HTTP Only Cookies"))
                .externalDocs(new ExternalDocumentation()
                        .description("Documentação Completa")
                        .url("/swagger-ui.html"));
    }
}