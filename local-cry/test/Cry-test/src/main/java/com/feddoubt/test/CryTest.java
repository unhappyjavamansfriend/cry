package com.feddoubt.test;

import pojos.CRY;

import java.util.Arrays;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Collectors;

public class CryTest {
    private static final int ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;

    public static void main(String[] args) throws Exception {

        //oldfe01@outlook.com
        //'9C2Q#D8kJn!,cc
        System.out.println("====== method1 =====");
        CRY cry = new CRY();
        cry.setAccount("5wRW41658@outlook.com");
        cry.setOriginalPassword("aew4twe1840u5uj2poi23$$$#$#434VVdc");
        method1(cry);
        String result = cry.getResult();
        System.out.println("====== method2 =====");
        method2(result);
    }

    private static void method1(CRY cry) throws Exception {
        letgoen(cry);
    }

    private static void method2(String result) throws Exception {
        CRY cry = new CRY();
        cry.setUserId(result.split(":")[0]);
        String userId = cry.getUserId();
        String salt = userId.substring(8, 16);
        cry.setSalt(salt);
        cry.setOriginalPasswordlen(userId.substring(userId.length() - 2));
        String originalPasswordlen = cry.getOriginalPasswordlen();
        cry.setAccount(result.split(":")[1]);
        cry.setResult(result.split(":")[2]);
        cry.setSecretKeyStr(result.split(":")[3]);
        cry.setIvSpecStr(result.split(":")[4]);
        cry.setEncryptedPassword(result.split(":")[5]);
        String combinedString = letgode(cry);
        cry.setCombinedPassword(combinedString);

        // 使用範例
        String extracted = extractPasswordSegments(combinedString);
        cry.setOriginalPassword(extracted);
        cry.setResult2();
        System.out.println("final result: " + cry.getResult());
    }

    private static void getlen() throws Exception {
        String uuid = "f798295a-ec81-462a-a8dc-e9a69a7d647f-12";
        String lastCharString = uuid.substring(uuid.length() - 2);
        System.out.println(lastCharString); // 輸出: 12
    }

    private static String letgode(CRY cry) throws Exception {
        // 從 Base64 字串還原 SecretKey
        String secretKeyString = cry.getSecretKeyStr();
        byte[] decodedKey = Base64.getDecoder().decode(secretKeyString);
        SecretKey secretKey = new SecretKeySpec(decodedKey, "AES");

        // 從 Base64 字串還原 IV
        String ivString = cry.getIvSpecStr();
        byte[] ivBytes = Base64.getDecoder().decode(ivString);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        String encryptedPassword = cry.getEncryptedPassword();

        String decryptedPassword = decrypt(encryptedPassword, secretKey, ivSpec);
//        System.out.println("decryptedPassword: " + decryptedPassword);
        return decryptedPassword;
    }

    private static void letgoen(CRY cry) throws Exception {
        String originalPassword = cry.getOriginalPassword();

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
        SecretKey secretKey = generateAESKey();
        cry.setSecretKey(secretKey);

        // 生成IV
        byte[] iv = generateIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cry.setIvSpec(ivSpec);

        // 加密
        String encryptedPassword = encrypt(combinedPassword, secretKey, ivSpec);
        cry.setSecretKeyStr(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        cry.setIvSpecStr(Base64.getEncoder().encodeToString(iv));
        cry.setEncryptedPassword(encryptedPassword);
        cry.setResult1();
        System.out.println("final result: " + cry.getResult());
    }

    // 將字串拆分為四段
    private static String[] splitIntoFourParts(String input) {
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
    private static String combineSegments(String[] passwordSegments, String[] saltSegments) {
        StringBuilder combined = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            combined.append(passwordSegments[i]).append(saltSegments[i]);
        }
        return combined.toString();
    }


    // 回推
    private static String extractPasswordSegments(String combinedString) {
        // 将字符串分成四段
        String[] segments = splitIntoFourParts(combinedString);

        // 过滤掉每段最后两个字符并串接
        String result = Arrays.stream(segments)
                .map(segment -> segment.substring(0, segment.length() - 2)) // 移除每段最后两个字符
                .collect(Collectors.joining()); // 拼接所有段

        return result;
    }

    public static String hashPasswordWithSalt(String password, String salt) {
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
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // 生成16字節的IV
    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // 加密方法
    public static String encrypt(String strToEncrypt, SecretKey secretKey, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密方法
    public static String decrypt(String strToDecrypt, SecretKey secretKey, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(strToDecrypt));
        return new String(decryptedBytes);
    }

    private static void test(CRY cry) throws Exception {
        String originalPassword = "MySecretPassword123!";

        // 生成鹽
        String userId = UUID.randomUUID().toString();
        String salt = userId.substring(8, 16);

        // 加鹽加密
//        String hashedPassword = hashPasswordWithSalt(originalPassword, salt);
//
        System.out.println("原始密碼: " + originalPassword);
        System.out.println("userId: " + userId);
//        System.out.println("鹽: " + salt);
//        System.out.println("加鹽哈希後的密碼: " + hashedPassword);


        // 將密碼拆分為四段
        String[] passwordSegments = splitIntoFourParts(originalPassword);
        String[] saltSegments = splitIntoFourParts(salt);

        // 組合
        String combinedPassword = combineSegments(passwordSegments, saltSegments);

        // 生成密鑰
        SecretKey secretKey = generateAESKey();

        // 生成IV
        byte[] iv = generateIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 加密
        String encryptedPassword = encrypt(combinedPassword, secretKey, ivSpec);
        // 打印結果
        System.out.println("加密密鑰: " + combinedPassword);
        System.out.println("加密密鑰: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));
        System.out.println("加密後字串: " + encryptedPassword);

        // 解密
        String decryptedPassword = decrypt(encryptedPassword, secretKey, ivSpec);
        // 打印結果
        System.out.println("解密後字串: " + decryptedPassword);
        // uuid:account:repo:secretKey:ivSpec:encryptedPassword
        String format = String.format("%s:%s:%s:%s:%s:%s",userId);
        System.out.println("final result: " + decryptedPassword);
    }

}
