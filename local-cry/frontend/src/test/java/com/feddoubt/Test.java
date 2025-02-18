package com.feddoubt;

import com.feddoubt.common.config.message.CustomHttpStatus;
import com.feddoubt.cry.ex.CustomException;

public class Test {
    public static void main(String[] args) {
//        System.out.println("decrypt".toUpperCase());
//        System.out.println("e24668a3-51b4-4be2-5".length());
//        System.out.println("175ac1e1-c2f0-47e5-b7bb-54221843ade1-20:e24668a3-51b4-4be2-5:e24668a3-51b4-4be2-5:4hIf7JnJm+WdLj7BlbxVvNgX2+8XzrXh1A/z669c/rQ=:zZCI8vANX6wRlndNNpRcjA==:hF3vD92y4WBuV0kAzhohwZ8qfFwI9YR1XWgZPvUsZTM=".length());
//        System.out.println("ae93530b-4059-4e64-ad48-02b29737f490-20:e24668a3-51b4-4be2-5:wfwe24668a3-4-wqe2-5:1mE14eL0tuI5xhA1tzvPdefIlkpySGzcOW6A0I91m2k=:vm4Gd/WgR6mDMaKXIrtrVQ==:YCSPaFBNmDHEZVDG1sOzJRawPDDP0Pc5zxzzouBLuu8=".length());

        try {
            String result = "a:s::12:45:12";
            int length = result.split(":").length;
            System.out.println(length);
//            String split = result.split(":")[5];
//            System.out.println(split);
            String salt = "asdae".substring(8, 16);
        } catch (StringIndexOutOfBoundsException e) {
            throw new CustomException(CustomHttpStatus.INVALID_REQUEST_DATA);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new CustomException(CustomHttpStatus.DECRYPT_COLON_CONFLICT);
        }

    }
}
