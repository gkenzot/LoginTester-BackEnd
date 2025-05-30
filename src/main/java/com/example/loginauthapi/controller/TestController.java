package com.example.loginauthapi.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @Autowired
    private DataSource dataSource;

    @GetMapping("/ping")
    public ResponseEntity<String> ping() {
        return ResponseEntity.ok("Backend está respondendo!");
    }

    @GetMapping("/database")
    public ResponseEntity<String> testDatabase() {
        try {
            Connection connection = dataSource.getConnection();
            connection.close();
            return ResponseEntity.ok("Conexão com o banco de dados estabelecida com sucesso!");
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Erro ao conectar com o banco de dados: " + e.getMessage());
        }
    }
} 