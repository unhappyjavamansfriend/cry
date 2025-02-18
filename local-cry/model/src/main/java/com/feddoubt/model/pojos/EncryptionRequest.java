package com.feddoubt.model.pojos;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Encryption request")
public class EncryptionRequest {
    @Schema(description = "Encrypted key", required = true)
    private String encryptedKey;
    @Schema(description = "Encrypted data", required = true)
    private String encryptedData;
}
