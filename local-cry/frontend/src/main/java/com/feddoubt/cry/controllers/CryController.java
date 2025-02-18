package com.feddoubt.cry.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.feddoubt.common.config.message.CustomHttpStatus;
import com.feddoubt.common.config.message.ResponseUtils;
import com.feddoubt.cry.ex.CustomException;
import com.feddoubt.cry.services.CryService;
import com.feddoubt.cry.services.EncryptionService;
import com.feddoubt.model.dtos.CryDto;
import com.feddoubt.model.pojos.EncryptionRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
@Slf4j
@RestController
@RequestMapping("/api/v1/cry")
@Tag(name = "crypt API")
public class CryController {

    private final CryService cryService;

    private final EncryptionService encryptionService;

    public CryController(CryService cryService , EncryptionService encryptionService){
        this.cryService = cryService;
        this.encryptionService = encryptionService;
    }

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Operation(
            summary = "Encrypt data",
            description = "Encrypts the provided data using the system's encryption mechanism",
            security = @SecurityRequirement(name = "Bearer Authentication"),
            parameters = {
                    @Parameter(
                            name = "Authorization",
                            description = "Bearer token",
                            required = true,
                            in = ParameterIn.HEADER,
                            example = "Bearer eyJhbGciOiJIUzI1NiJ9..."
                    )
            },
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = EncryptionRequest.class),
                            examples = {
                                    @ExampleObject(
                                            name = "Basic Example",
                                            summary = "A basic encryption request",
                                            value = """
                        {
                            "encryptedKey": "basic-key",
                            "encryptedData": "basic-data"
                        }
                        """
                                    ),
                                    @ExampleObject(
                                            name = "Complex Example",
                                            summary = "A more complex encryption request",
                                            value = """
                        {
                            "encryptedKey": "complex-encrypted-key-value",
                            "encryptedData": "complex-encrypted-data-value"
                        }
                        """
                                    )
                            }
                    )
            )
    )
    @PostMapping(value = "/encrypt", consumes = {"application/json", "application/octet-stream"})
    public ResponseEntity<?> encrypt(@RequestBody @Valid EncryptionRequest data) {
        CryDto cryDto = requestData(data);
        return ResponseEntity.ok(ResponseUtils.success(cryService.encrypt(cryDto)));
    }
    //lambda
//    public ResponseEntity<?> encrypt(@RequestBody @Valid byte[] data) {
//        CryDto cryDto = requestData(data);
//        return ResponseEntity.ok(ResponseUtils.success(cryService.encrypt(cryDto)));
//    }

    @Operation(
        summary = "Encrypt data",
        description = "Encrypts the provided data using the system's encryption mechanism",
        security = @SecurityRequirement(name = "Bearer Authentication"),
        parameters = {
            @Parameter(
                name = "Authorization",
                description = "Bearer token",
                required = true,
                in = ParameterIn.HEADER,
                example = "Bearer eyJhbGciOiJIUzI1NiJ9..."
            )
        },
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = EncryptionRequest.class),
                examples = {
                    @ExampleObject(
                        name = "Basic Example",
                        summary = "A basic encryption request",
                        value = """
                        {
                            "encryptedKey": "basic-key",
                            "encryptedData": "basic-data"
                        }
                        """
                    ),
                    @ExampleObject(
                        name = "Complex Example",
                        summary = "A more complex encryption request",
                        value = """
                        {
                            "encryptedKey": "complex-encrypted-key-value",
                            "encryptedData": "complex-encrypted-data-value"
                        }
                        """
                    )
                }
            )
        )
    )
    @io.swagger.v3.oas.annotations.media.Schema(
            description = "Encryption request data"
    )
    @PostMapping(value = "/decrypt", consumes = {"application/json", "application/octet-stream"})
    public ResponseEntity<?> decrypt(@RequestBody @Valid EncryptionRequest data) {
        CryDto cryDto = requestData(data);
        return ResponseEntity.ok(ResponseUtils.success(cryService.decrypt(cryDto)));
    }
    //lambda
//    public ResponseEntity<?> decrypt(@RequestBody @Valid byte[] data) {
//        CryDto cryDto = requestData(data);
//        return ResponseEntity.ok(ResponseUtils.success(cryService.decrypt(cryDto)));
//    }

    private CryDto requestData(EncryptionRequest request){
        try {
//            log.info("data:{}",data);
//            EncryptionRequest request = objectMapper.readValue(data, EncryptionRequest.class);
            if (request == null || StringUtils.isEmpty(request.getEncryptedKey())
                    || StringUtils.isEmpty(request.getEncryptedData())) {
                throw new CustomException(CustomHttpStatus.INVALID_REQUEST_DATA);
            }

            String processedData = encryptionService.processEncryptedData(
                    request.getEncryptedKey(),
                    request.getEncryptedData()
            );
            log.info("processedData:{}",processedData);

            CryDto cryDto = objectMapper.readValue(processedData, CryDto.class);
            log.info("cryDto:{}",cryDto);
            return cryDto;
        } catch (JsonProcessingException e) {
            log.error("JSON 解析錯誤: {}", e.getMessage());
            throw new CustomException(CustomHttpStatus.INVALID_JSON_FORMAT);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}