package com.fedoubt.pojos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EncryptionRequest {
    private String encryptedKey;
    private String encryptedData;
}