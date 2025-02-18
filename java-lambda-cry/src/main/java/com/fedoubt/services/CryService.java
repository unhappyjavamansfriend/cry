package com.fedoubt.services;


import com.fedoubt.common.message.CustomHttpStatus;
import com.fedoubt.dtos.CryDto;
import com.fedoubt.ex.CustomException;
import com.fedoubt.pojos.Cry;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class CryService {
    private final int ITERATIONS = 10000;
    private final int KEY_LENGTH = 256;

    public void checkdata(CryDto crydto ,boolean isDecrypt){
        log.info("dto:{}",crydto);
        if (crydto == null || StringUtils.isEmpty(crydto.getItemname())
                || StringUtils.isEmpty(crydto.getUsername())
                || StringUtils.isEmpty(crydto.getPassword())) {
            throw new CustomException(CustomHttpStatus.INVALID_REQUEST_DATA);
        }
        List<String> dataList = Optional.ofNullable(crydto.getDataList()).orElse(Collections.emptyList());
        if(isDecrypt){
            for (String data : dataList){
                if(data.length()< 20){
                    throw new CustomException(CustomHttpStatus.DATA_TOO_SHORT);
                }
                if(data.length() > 200){
                    throw new CustomException(CustomHttpStatus.DATA_TOO_LONG);
                }
            }
        }else{
            for (String data : dataList){
                if(data.length()< 4){
                    throw new CustomException(CustomHttpStatus.DATA_TOO_SHORT);
                }
                if(data.length() >= 20){
                    throw new CustomException(CustomHttpStatus.DATA_TOO_LONG);
                }
            }
        }
    }

    public String decrypt(CryDto crydto) {
        checkdata(crydto ,true);
        String result = crydto.getItemname();
        Cry cry = new Cry();
        String salt;
        if(!result.contains(":")){
            throw new CustomException(CustomHttpStatus.INVALID_REQUEST_DATA);
        }

        if(result.split(":").length > 6){
            throw new CustomException(CustomHttpStatus.DECRYPT_COLON_CONFLICT);
        }

        try {
            cry.setUserId(result.split(":")[0]);
            String userId = cry.getUserId();
            salt = userId.substring(8, 16);
            cry.setSalt(salt);
            cry.setOriginalPasswordlen(userId.substring(userId.length() - 2));
            cry.setAccount(result.split(":")[1]);
            cry.setResult(result.split(":")[2]);
            cry.setSecretKeyStr(result.split(":")[3]);
            cry.setIvSpecStr(result.split(":")[4]);
            cry.setEncryptedPassword(result.split(":")[5]);
        } catch (ArrayIndexOutOfBoundsException | StringIndexOutOfBoundsException e) {
            throw new CustomException(CustomHttpStatus.INVALID_REQUEST_DATA);
        }

        // 從 Base64 字串還原 SecretKey
        String secretKeyString = cry.getSecretKeyStr();
        byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
        SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");

        // 從 Base64 字串還原 IV
        String ivString = cry.getIvSpecStr();
        byte[] ivBytes = Base64.getDecoder().decode(ivString);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        String encryptedPassword = cry.getEncryptedPassword();

        String decryptedPassword = null;
        try {
            decryptedPassword = decrypt(encryptedPassword, secretKey, ivSpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        cry.setCombinedPassword(decryptedPassword);

        // 使用範例
        String extracted = extractPasswordSegments(decryptedPassword);
        cry.setOriginalPassword(extracted);
        String s = extracted.substring(0, extracted.length() / 2)
                + salt.substring(salt.length() / 2, salt.length())
                + salt.substring(0, salt.length() / 2)
                + extracted.substring(extracted.length() / 2, extracted.length());
        cry.setOriginalPassword(s);
        cry.setResult2();
        log.info("final result:{}",cry.getResult());
        return cry.getResult();
    }

    public String encrypt(CryDto crydto) {
        checkdata(crydto ,false);
        Cry cry = new Cry();
        if(crydto.getItemname().contains(":")
                || crydto.getUsername().contains(":")
                || crydto.getPassword().contains(":")){
            throw new CustomException(CustomHttpStatus.ENCRYPT_COLON_CONFLICT);
        }

        String originalPassword = crydto.getPassword();
        cry.setOriginalPassword(originalPassword);
        cry.setAccount(crydto.getUsername());
        cry.setProject(crydto.getItemname());
        // 生成鹽
        String userId = UUID.randomUUID().toString();
        String salt = userId.substring(8, 16);
        cry.setUserId(userId);
        cry.setOriginalPasswordlen(""+originalPassword.length());
        cry.setSalt(salt);
        cry.setUserId(userId+"-"+cry.getOriginalPasswordlen());

        // 將密碼拆分為四段
        String[] passwordSegments = splitIntoFourParts(originalPassword);
        String[] saltSegments = splitIntoFourParts(salt);

        // 組合
        String combinedPassword = combineSegments(passwordSegments, saltSegments);
        cry.setCombinedPassword(combinedPassword);

        // 生成密鑰
        SecretKey secretKey = null;
        try {
            secretKey = generateAESKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        cry.setSecretKey(secretKey);

        // 生成IV
        byte[] iv = generateIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cry.setIvSpec(ivSpec);

        // 加密
        String encryptedPassword = null;
        try {
            encryptedPassword = encrypt(combinedPassword, secretKey, ivSpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        cry.setSecretKeyStr(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        cry.setIvSpecStr(Base64.getEncoder().encodeToString(iv));
        cry.setEncryptedPassword(encryptedPassword);
        cry.setResult1();
        log.info("final result:{}",cry.getResult());
        return cry.getResult();
    }

    // 將字串拆分為四段
    private String[] splitIntoFourParts(String input) {
        int length = input.length();
        int partLength = length / 4;

        String[] segments = new String[4];
        for (int i = 0; i < 4; i++) {
            int start = i * partLength;
            int end = (i == 3) ? length : (i + 1) * partLength;
            segments[i] = input.substring(start, end);
        }

        return segments;
    }

    // 交錯組合密碼和鹽的各個部分
    private String combineSegments(String[] passwordSegments, String[] saltSegments) {
        StringBuilder combined = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            combined.append(passwordSegments[i]).append(saltSegments[i]);
        }
        return combined.toString();
    }


    // 回推
    private String extractPasswordSegments(String combinedString) {
        // 将字符串分成四段
        String[] segments = splitIntoFourParts(combinedString);

        // 过滤掉每段最后两个字符并串接
        String result = Arrays.stream(segments)
                .map(segment -> segment.substring(0, segment.length() - 2)) // 移除每段最后两个字符
                .collect(Collectors.joining()); // 拼接所有段

        return result;
    }

    public String hashPasswordWithSalt(String password, String salt) {
        try {
            // 將密碼和鹽結合
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt.getBytes(),
                    ITERATIONS,
                    KEY_LENGTH
            );

            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = skf.generateSecret(spec).getEncoded();

            // 返回 Base64 編碼的哈希值
            return Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    // 生成AES-256密鑰
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // 生成16字節的IV
    public byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // 加密方法
    public String encrypt(String strToEncrypt, SecretKey secretKey, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public String decrypt(String strToDecrypt, SecretKey secretKey, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(strToDecrypt));
        return new String(decryptedBytes);
    }
}
