package com.feddoubt.cry.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileNotFoundException;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/key")
@Tag(name = "key API")
public class PublicKeyController {

    private static final Logger logger = LoggerFactory.getLogger(PublicKeyController.class);

    @Value("${key.path.public:src/main/resources/public_key.pem}")
    private String publicKeyPath;

    @Operation(
        summary = "public_key",
        description = "E2EE - RSA public_key to encrypt frontend AES key",
        security = @SecurityRequirement(name = "Bearer Authentication"),
        parameters = {
            @Parameter(
                name = "Authorization",
                description = "Bearer token",
                required = true,
                in = ParameterIn.HEADER,
                example = "Bearer eyJhbGciOiJIUzI1NiJ9..."
            )
        }
    )
    @GetMapping("/public")
    public ResponseEntity<?> getPublicKey() {
        try {
            logger.info("publicKeyPath:{}",publicKeyPath);
            // 使用 ClassPathResource 來讀取資源檔案
            Resource resource = new ClassPathResource(publicKeyPath);
            String publicKey = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
            return ResponseEntity.ok(publicKey);

        } catch (FileNotFoundException e) {
            logger.error("Public key file not found: {}", publicKeyPath, e);
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("Public key file not found");

        } catch (IOException e) {
            logger.error("Error reading public key file: {}", publicKeyPath, e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error reading public key file");

        } catch (Exception e) {
            logger.error("Unexpected error while reading public key: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Internal server error");
        }
    }
}