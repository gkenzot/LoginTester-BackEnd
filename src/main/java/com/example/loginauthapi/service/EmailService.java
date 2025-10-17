package com.example.loginauthapi.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    
    private final JavaMailSender mailSender;
    
    @Value("${app.email.from}")
    private String fromEmail;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    public void sendPasswordResetCode(String toEmail, String resetCode, String userName) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Código de Redefinição - LoginTester");
            
            String htmlContent = buildPasswordResetCodeHtml(userName, resetCode);
            helper.setText(htmlContent, true);
            
            mailSender.send(message);
            log.info("Password reset code sent successfully to: {}", toEmail);
            
        } catch (MessagingException e) {
            log.error("Failed to send password reset code to: {}", toEmail, e);
            throw new RuntimeException("Erro ao enviar código de redefinição", e);
        }
    }
    
    public void sendEmailVerificationEmail(String toEmail, String verificationToken, String userName) {
        String verificationUrl = frontendUrl + "/verify-email?token=" + verificationToken;
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Verificar Email - LoginTester");
            
            String htmlContent = buildEmailVerificationHtml(userName, verificationUrl);
            helper.setText(htmlContent, true);
            
            mailSender.send(message);
            log.info("Email verification sent successfully to: {}", toEmail);
            
        } catch (MessagingException e) {
            log.error("Failed to send email verification to: {}", toEmail, e);
            throw new RuntimeException("Erro ao enviar email de verificação", e);
        }
    }
    
    public void sendEmailVerificationCode(String toEmail, String verificationCode, String userName) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Código de Verificação - LoginTester");
            
            String htmlContent = buildEmailVerificationCodeHtml(userName, verificationCode);
            helper.setText(htmlContent, true);
            
            mailSender.send(message);
            log.info("Email verification code sent successfully to: {}", toEmail);
            
        } catch (MessagingException e) {
            log.error("Failed to send email verification code to: {}", toEmail, e);
            throw new RuntimeException("Erro ao enviar código de verificação", e);
        }
    }
    
    private String buildPasswordResetCodeHtml(String userName, String resetCode) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Código de Redefinição</title>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
                        .content { padding: 30px; background: #f8fafc; border-radius: 0 0 8px 8px; }
                        .code-box { background: #1f2937; color: #f9fafb; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; font-family: 'Courier New', monospace; font-size: 32px; font-weight: bold; letter-spacing: 4px; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
                        .warning { background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 6px; margin: 20px 0; }
                        .info { background: #dbeafe; border: 1px solid #3b82f6; padding: 15px; border-radius: 6px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔐 LoginTester</h1>
                        </div>
                        <div class="content">
                            <h2>Olá, %s!</h2>
                            <p>Recebemos uma solicitação para redefinir a senha da sua conta.</p>
                            <p>Use o código abaixo para continuar:</p>
                            <div class="code-box">%s</div>
                            <div class="info">
                                <p><strong>ℹ️ Este código expira em 10 minutos.</strong></p>
                                <p>Digite este código na tela de redefinição de senha.</p>
                            </div>
                            <div class="warning">
                                <p><strong>⚠️ Se você não solicitou esta redefinição, ignore este email.</strong></p>
                                <p>Não compartilhe este código com ninguém.</p>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Este é um email automático, não responda.</p>
                            <p>LoginTester - Sistema de Autenticação</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(userName, resetCode);
    }
    
    private String buildEmailVerificationHtml(String userName, String verificationUrl) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Verificar Email</title>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #059669; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
                        .content { padding: 30px; background: #f0fdf4; border-radius: 0 0 8px 8px; }
                        .button { display: inline-block; background: #059669; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; font-weight: bold; }
                        .button:hover { background: #047857; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
                        .info { background: #dbeafe; border: 1px solid #3b82f6; padding: 15px; border-radius: 6px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>✅ LoginTester</h1>
                        </div>
                        <div class="content">
                            <h2>Olá, %s!</h2>
                            <p>Bem-vindo ao LoginTester! Para ativar sua conta, verifique seu endereço de email.</p>
                            <p>Clique no botão abaixo para verificar seu email:</p>
                            <a href="%s" class="button">Verificar Email</a>
                            <div class="info">
                                <p><strong>ℹ️ Este link expira em 24 horas.</strong></p>
                                <p>Após a verificação, você terá acesso completo ao sistema.</p>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Este é um email automático, não responda.</p>
                            <p>LoginTester - Sistema de Autenticação</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(userName, verificationUrl);
    }
    
    private String buildEmailVerificationCodeHtml(String userName, String verificationCode) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Código de Verificação</title>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #059669; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
                        .content { padding: 30px; background: #f0fdf4; border-radius: 0 0 8px 8px; }
                        .code-box { background: #1f2937; color: #f9fafb; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; font-family: 'Courier New', monospace; font-size: 32px; font-weight: bold; letter-spacing: 4px; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
                        .warning { background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 6px; margin: 20px 0; }
                        .info { background: #dbeafe; border: 1px solid #3b82f6; padding: 15px; border-radius: 6px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>✅ LoginTester</h1>
                        </div>
                        <div class="content">
                            <h2>Olá, %s!</h2>
                            <p>Bem-vindo ao LoginTester! Para ativar sua conta, verifique seu endereço de email.</p>
                            <p>Use o código abaixo para verificar seu email:</p>
                            <div class="code-box">%s</div>
                            <div class="info">
                                <p><strong>ℹ️ Este código expira em 10 minutos.</strong></p>
                                <p>Digite este código na tela de verificação de email.</p>
                            </div>
                            <div class="warning">
                                <p><strong>⚠️ Se você não criou esta conta, ignore este email.</strong></p>
                                <p>Não compartilhe este código com ninguém.</p>
                            </div>
                        </div>
                        <div class="footer">
                            <p>Este é um email automático, não responda.</p>
                            <p>LoginTester - Sistema de Autenticação</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(userName, verificationCode);
    }
}