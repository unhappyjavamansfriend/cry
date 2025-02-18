package com.fedoubt.pojos;

import lombok.Data;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.util.List;

@Data
public class Cry {
    private String userId;
    private String account;
    private String project;
    private String originalPassword;
    private String originalPasswordlen;
    private String salt;
    private String combinedPassword;
    private SecretKey secretKey;
    private String secretKeyStr;
    private IvParameterSpec ivSpec;
    private String ivSpecStr;
    private String encryptedPassword;
    private String result;

    // uuid:account:repo:secretKey:ivSpec:encryptedPassword
    public void setResult1() {
        List<String> words = Arrays.asList(this.userId,this.account,this.project == null ? "" : this.project,this.secretKeyStr,this.ivSpecStr,this.encryptedPassword);
        this.result = String.join(":", words);
    }

    public void setResult2() {
        List<String> words = Arrays.asList(this.userId,this.project == null ? "" : this.project,this.account,this.originalPassword);
        this.result = String.join(":", words);
    }
}
