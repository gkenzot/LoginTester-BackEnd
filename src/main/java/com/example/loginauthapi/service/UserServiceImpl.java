package com.example.loginauthapi.service;

import com.example.loginauthapi.domain.User;
import com.example.loginauthapi.domain.UserRole;
import com.example.loginauthapi.dto.*;
import jakarta.annotation.PostConstruct;
import com.example.loginauthapi.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.*;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordValidator passwordValidator;
    private final Path profilePhotoBaseDir;
    private final long maxProfilePhotoSizeBytes;

    private static final Set<String> ALLOWED_IMAGE_CONTENT_TYPES = Set.of(
        "image/jpeg",
        "image/png",
        "image/webp"
    );

    private static final Set<String> SUPPORTED_LANGUAGES = Set.of("pt-BR", "en-US");

    public UserServiceImpl(
        UserRepository userRepository,
        PasswordEncoder passwordEncoder,
        PasswordValidator passwordValidator,
        @Value("${app.upload.profile-photo-dir:uploads/profile-photos}") String profilePhotoDir,
        @Value("${app.upload.profile-photo-max-size-bytes:2097152}") long maxProfilePhotoSizeBytes
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordValidator = passwordValidator;
        String resolvedDir = (profilePhotoDir == null || profilePhotoDir.isBlank())
            ? "uploads/profile-photos"
            : profilePhotoDir;
        this.profilePhotoBaseDir = Path.of(resolvedDir).toAbsolutePath().normalize();
        this.maxProfilePhotoSizeBytes = maxProfilePhotoSizeBytes > 0 ? maxProfilePhotoSizeBytes : 2097152;
    }

    @PostConstruct
    void ensureUploadDirectoryExists() {
        try {
            Files.createDirectories(profilePhotoBaseDir);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create profile photo upload directory", e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDTO getCurrentUser(String email) {
        User user = findUserByEmail(email);
        return mapToUserResponseDTO(user);
    }

    /**
     * Atualiza dados do usuário logado (nome, idioma). Apenas o próprio usuário pode alterar.
     * Nome validado via @Valid no controller; checagem aqui é defensiva (chamadas diretas ao service).
     */
    @Override
    @Transactional
    public UserResponseDTO updateUserInfo(String email, UpdateUserDTO dto) {
        if (dto.name() == null || dto.name().trim().isEmpty()) {
            throw new ResponseStatusException(BAD_REQUEST, "O nome não pode estar vazio");
        }
        User user = findUserByEmail(email);
        user.setName(dto.name().trim());
        applyPreferredLanguageIfPresent(user, dto.preferredLanguage());
        User updatedUser = userRepository.save(user);
        return mapToUserResponseDTO(updatedUser);
    }

    @Override
    @Transactional
    public void updatePassword(String email, UpdatePasswordDTO dto) {
        if (!dto.passwordsMatch()) {
            throw new ResponseStatusException(BAD_REQUEST, "Nova senha e confirmação não coincidem");
        }
        passwordValidator.validate(dto.newPassword());

        User user = findUserByEmail(email);
        if (!passwordEncoder.matches(dto.currentPassword(), user.getPassword())) {
            throw new ResponseStatusException(UNAUTHORIZED, "Senha atual incorreta");
        }
        user.setPassword(passwordEncoder.encode(dto.newPassword()));
        userRepository.save(user);
    }

    @Override
    @Transactional
    public UserResponseDTO uploadProfilePhoto(String email, MultipartFile file) {
        validateProfilePhotoFile(file);

        User user = findUserByEmail(email);
        String extension = mapContentTypeToExtension(file.getContentType());
        String fileName = user.getId() + "_" + UUID.randomUUID() + extension;
        Path destination = profilePhotoBaseDir.resolve(fileName).normalize();

        ensurePathInsideUploadDirectory(destination);

        try {
            Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);
            deleteOldProfilePhotoIfExists(user.getProfilePhotoPath());
            user.setProfilePhotoPath(fileName);
            User savedUser = userRepository.save(user);
            return mapToUserResponseDTO(savedUser);
        } catch (IOException e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, "Erro ao salvar foto de perfil");
        }
    }

    @Override
    @Transactional
    public UserResponseDTO removeProfilePhoto(String email) {
        User user = findUserByEmail(email);
        deleteOldProfilePhotoIfExists(user.getProfilePhotoPath());
        user.setProfilePhotoPath(null);
        User savedUser = userRepository.save(user);
        return mapToUserResponseDTO(savedUser);
    }

    @Override
    @Transactional(readOnly = true)
    public Resource getProfilePhoto(String email) {
        return getProfilePhotoResource(email).resource();
    }

    @Override
    @Transactional(readOnly = true)
    public String getProfilePhotoContentType(String email) {
        return getProfilePhotoResource(email).contentType();
    }

    @Override
    @Transactional(readOnly = true)
    public ProfilePhotoResult getProfilePhotoResource(String email) {
        User user = findUserByEmail(email);
        String fileName = user.getProfilePhotoPath();
        if (fileName == null || fileName.isBlank()) {
            throw new ResponseStatusException(NOT_FOUND, "Usuário não possui foto de perfil");
        }
        Path photoPath = profilePhotoBaseDir.resolve(fileName).normalize();
        ensurePathInsideUploadDirectory(photoPath);
        try {
            if (!Files.exists(photoPath) || !Files.isReadable(photoPath)) {
                throw new ResponseStatusException(NOT_FOUND, "Foto de perfil não encontrada");
            }
            String contentType = Files.probeContentType(photoPath);
            String type = contentType != null ? contentType : "application/octet-stream";
            return new ProfilePhotoResult(new UrlResource(photoPath.toUri()), type);
        } catch (IOException e) {
            throw new ResponseStatusException(INTERNAL_SERVER_ERROR, "Erro ao ler foto de perfil");
        }
    }
    
    // Admin methods
    @Override
    @Transactional(readOnly = true)
    public List<UserResponseDTO> getAllUsers() {
        List<User> users = userRepository.findAll();
        return users.stream()
                .map(this::mapToUserResponseDTO)
                .collect(Collectors.toList());
    }
    
    @Override
    @Transactional(readOnly = true)
    public UserResponseDTO getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Usuário não encontrado"));
        return mapToUserResponseDTO(user);
    }
    
    /**
     * Atualiza usuário por ID. Apenas ADMIN pode chamar (controller protegido por flag USER_MANAGE/role).
     * Permite alterar nome, role, accessFlags e preferredLanguage.
     */
    @Override
    @Transactional
    public UserResponseDTO updateUserById(UUID userId, UpdateUserDTO dto) {
        if (dto.name() == null || dto.name().trim().isEmpty()) {
            throw new ResponseStatusException(BAD_REQUEST, "O nome não pode estar vazio");
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Usuário não encontrado"));
        
        user.setName(dto.name().trim());
        if (dto.accessFlags() != null) {
            user.getAccessFlags().clear();
            user.getAccessFlags().addAll(dto.accessFlags());
        }
        if (dto.role() != null && !dto.role().isBlank()) {
            try {
                user.setRole(UserRole.valueOf(dto.role().trim().toUpperCase()));
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(BAD_REQUEST, "Role inválida. Use: ADMIN, USER ou UNVERIFIED");
            }
        }
        applyPreferredLanguageIfPresent(user, dto.preferredLanguage());
        User updatedUser = userRepository.save(user);
        return mapToUserResponseDTO(updatedUser);
    }
    
    @Override
    @Transactional
    public void deleteUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Usuário não encontrado"));
        
        userRepository.delete(user);
    }
    
    @Override
    public UserResponseDTO toUserResponseDTO(User user) {
        return mapToUserResponseDTO(user);
    }

    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Usuário não encontrado"));
    }

    private UserResponseDTO mapToUserResponseDTO(User user) {
        Set<String> flags = user.getAccessFlags();
        List<String> accessFlagsList = flags != null ? new ArrayList<>(flags) : List.of();
        String profilePhotoUrl = user.getProfilePhotoPath() != null && !user.getProfilePhotoPath().isBlank()
            ? "/api/user/me/photo"
            : null;
        String preferredLanguage = user.getPreferredLanguage() != null && !user.getPreferredLanguage().isBlank()
            ? user.getPreferredLanguage()
            : "pt-BR";
        return new UserResponseDTO(
            user.getId().toString(),
            user.getName(),
            user.getEmail(),
            user.getRole().name(),
            preferredLanguage,
            profilePhotoUrl,
            accessFlagsList
        );
    }

    private void validateProfilePhotoFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new ResponseStatusException(BAD_REQUEST, "Arquivo de foto é obrigatório");
        }
        if (file.getSize() > maxProfilePhotoSizeBytes) {
            long maxMb = maxProfilePhotoSizeBytes / (1024 * 1024);
            throw new ResponseStatusException(BAD_REQUEST,
                "Foto excede o tamanho máximo permitido (" + (maxMb > 0 ? maxMb + "MB" : maxProfilePhotoSizeBytes + " bytes") + ")");
        }
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_IMAGE_CONTENT_TYPES.contains(contentType)) {
            throw new ResponseStatusException(BAD_REQUEST, "Formato inválido. Use JPG, PNG ou WEBP");
        }
    }

    private String mapContentTypeToExtension(String contentType) {
        return switch (contentType) {
            case "image/jpeg" -> ".jpg";
            case "image/png" -> ".png";
            case "image/webp" -> ".webp";
            default -> throw new ResponseStatusException(BAD_REQUEST, "Formato inválido. Use JPG, PNG ou WEBP");
        };
    }

    private void deleteOldProfilePhotoIfExists(String existingPath) {
        if (existingPath == null || existingPath.isBlank()) {
            return;
        }
        try {
            Path oldPath = profilePhotoBaseDir.resolve(existingPath).normalize();
            ensurePathInsideUploadDirectory(oldPath);
            Files.deleteIfExists(oldPath);
        } catch (IOException ignored) {
            // best-effort cleanup; não impede atualização da foto
        }
    }

    private void ensurePathInsideUploadDirectory(Path path) {
        if (!path.startsWith(profilePhotoBaseDir)) {
            throw new ResponseStatusException(BAD_REQUEST, "Caminho de arquivo inválido");
        }
    }

    private void applyPreferredLanguageIfPresent(User user, String preferredLanguage) {
        if (preferredLanguage == null || preferredLanguage.isBlank()) {
            return;
        }
        String value = preferredLanguage.trim();
        if (!SUPPORTED_LANGUAGES.contains(value)) {
            throw new ResponseStatusException(
                BAD_REQUEST,
                "Idioma inválido. Use: pt-BR ou en-US"
            );
        }
        user.setPreferredLanguage(value);
    }
}