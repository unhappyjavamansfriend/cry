package com.feddoubt.cry.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

public class RSAKeyGenerator {

    private static final int KEY_SIZE = 2048; // 建議 2048 或 4096

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        // 1. 生成 RSA 金鑰對
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 2. 將公私鑰轉換為 PEM 格式
        String privateKeyPEM = convertToPEM(privateKey.getEncoded(), "PRIVATE KEY");
        String publicKeyPEM = convertToPEM(publicKey.getEncoded(), "PUBLIC KEY");

        // 3. 存入文件
        saveToFile("D:\\workspace\\key\\private_key.pem", privateKeyPEM);
        saveToFile("D:\\workspace\\key\\public_key.pem", publicKeyPEM);

        System.out.println("RSA 公私鑰生成完成！\n");
        System.out.println("public_key:\n" + publicKeyPEM);
        System.out.println("private_key:\n" + privateKeyPEM);
    }

    // 將金鑰轉換為 PEM 格式
    private static String convertToPEM(byte[] keyBytes, String type) {
        String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
        return "-----BEGIN " + type + "-----\n" +
                encodedKey.replaceAll("(.{64})", "$1\n") + // 每 64 字符換行
                "\n-----END " + type + "-----";
    }

    // 存入文件
    private static void saveToFile(String filename, String content) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(content);
        }
    }
}
