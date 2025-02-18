package com.feddoubt.cry.ex;

import com.feddoubt.common.config.message.CustomHttpStatus;

public class CustomException extends RuntimeException {
    private final int statusCode;
    private final String reasonPhrase;

    public CustomException(CustomHttpStatus status) {
        super(status.getReasonPhrase()); // 設定錯誤訊息
        this.reasonPhrase = status.getReasonPhrase();
        this.statusCode = status.value();
    }

    public String getReasonPhrase() {
        return reasonPhrase;
    }

    public int getStatusCode() {
        return statusCode;
    }
}