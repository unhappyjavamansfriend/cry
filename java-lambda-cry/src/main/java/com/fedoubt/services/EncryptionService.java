package com.fedoubt.services;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
@Service
public class EncryptionService {

    /**
     * 1. 前端獲取後端的 RSA 公鑰
     * 2. 前端生成 AES 密鑰
     * 3. 前端用 RSA 公鑰加密 AES 密鑰
     * 4. 前端用 AES 加密實際數據
     * 5. 後端用 RSA 私鑰解密出 AES 密鑰
     * 6. 後端用解密出的 AES 密鑰解密數據
     */


    @Value("${key.path.private:src/main/resources/private_key.pem}")
    private String privateKeyPath;

    private RSAPrivateKey privateKey;

    @PostConstruct  // 改用 @PostConstruct 進行初始化
    public void init() throws Exception {
        this.privateKey = loadPrivateKey();
    }

    private RSAPrivateKey loadPrivateKey() throws Exception {
        try {
            // 使用 ClassPathResource 從 classpath 讀取
            Resource resource = new ClassPathResource(privateKeyPath);
            String privateKeyPEM = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()))
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            log.info("privateKeyPEM:{}", privateKeyPEM);

            // 解碼 Base64 編碼的私鑰
            byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);

            // 轉換為 PKCS8 格式的私鑰
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        } catch (Exception e) {
            log.error("Failed to load private key", e);
            throw new Exception("Failed to load private key: " + e.getMessage());
        }
    }

    public String processEncryptedData(String encryptedKey, String encryptedData)
            throws Exception {
        log.info("Encrypted AES key: {}", encryptedKey);
        log.info("Encrypted data: {}", encryptedData);
        return decrypt(encryptedKey, encryptedData);

    }

    // 完整的解密流程
    public String decrypt(String encryptedKey, String encryptedData) throws Exception {
        // 1. 先用 RSA 私鑰解密 AES 密鑰
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        String aesKeyHex = new String(decryptedKeyBytes);
        // 2. 使用解密後的 AES 密鑰來解密數據
        return decryptWithAES(encryptedData, aesKeyHex);
    }

    private String decryptWithAES(String encryptedData, String aesKeyHex) throws Exception {
        try {

            log.info("Step 1: Preparing AES key");
            log.info("Input AES key hex: {}", aesKeyHex);
            log.info("AES key hex length: {}", aesKeyHex.length());
            // 直接使用 hex string，不用額外轉換
            byte[] aesKey = hexStringToByteArray(aesKeyHex);

            // 確保 AES 金鑰是 32 bytes
            if (aesKey.length != 32) {
                throw new IllegalArgumentException("AES Key should be 32 bytes but got: " + aesKey.length);
            }

            log.info("\nStep 2: Examining encrypted data");
            byte[] cipherData = Base64.getDecoder().decode(encryptedData);


            // 確保密文長度正確
            if (cipherData.length < 16) {
                throw new IllegalArgumentException("Cipher data too short! Length: " + cipherData.length);
            }

            // 解析 IV 和密文
            byte[] iv = Arrays.copyOfRange(cipherData, 0, 16);
            byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);


            log.info("IV (Base64): {}", Base64.getEncoder().encodeToString(iv));
            log.info("Encrypted (Base64): {}", Base64.getEncoder().encodeToString(encrypted));

            // 確保密文長度是 16 的倍數
            if (encrypted.length % 16 != 0) {
                throw new IllegalArgumentException("Encrypted data length is not a multiple of 16 bytes.");
            }

            // 初始化 AES 解密
            SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");
            //  Java 中 PKCS5Padding 和 PKCS7Padding 在 AES CBC 模式下是等效的， Java 內建只支持 PKCS5Padding，所以保持 PKCS5Padding 也沒問題。
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            // 解密
            byte[] decryptedBytes = cipher.doFinal(encrypted);
            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);

            log.info("Decrypted JSON: {}", decrypted);
            return decrypted;


        } catch (Exception e) {
            log.error("\nDecryption failed: ", e);
            throw e;
        }
    }

    // 輔助方法：將 hex 字串轉換為 byte array
    private byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}