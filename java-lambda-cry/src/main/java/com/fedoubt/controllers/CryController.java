package com.fedoubt.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fedoubt.common.message.CustomHttpStatus;
import com.fedoubt.common.message.ResponseUtils;
import com.fedoubt.dtos.CryDto;
import com.fedoubt.ex.CustomException;
import com.fedoubt.pojos.EncryptionRequest;
import com.fedoubt.services.CryService;
import com.fedoubt.services.EncryptionService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
@Slf4j
@RestController
@RequestMapping("/api/v1/cry")
public class CryController {

    private final CryService cryService;

    private final EncryptionService encryptionService;

    public CryController(CryService cryService , EncryptionService encryptionService){
        this.cryService = cryService;
        this.encryptionService = encryptionService;
    }

    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping(value = "/encrypt", consumes = {"application/json", "application/octet-stream"})
    public ResponseEntity<?> encrypt(@RequestBody byte[] data) {
        CryDto cryDto = requestData(data);
        return ResponseEntity.ok(ResponseUtils.success(cryService.encrypt(cryDto)));
    }

    @PostMapping(value = "/decrypt", consumes = {"application/json", "application/octet-stream"})
    //lambda
    public ResponseEntity<?> decrypt(@RequestBody byte[] data) {
        CryDto cryDto = requestData(data);
        return ResponseEntity.ok(ResponseUtils.success(cryService.decrypt(cryDto)));
    }

    private CryDto requestData(byte[] data){
        try {
            log.info("data:{}",data);
            EncryptionRequest request = objectMapper.readValue(data, EncryptionRequest.class);
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