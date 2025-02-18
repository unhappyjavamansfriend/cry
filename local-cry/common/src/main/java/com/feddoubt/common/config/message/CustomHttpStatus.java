package com.feddoubt.common.config.message;

public enum CustomHttpStatus implements ApiStatus {
    INVALID_REQUEST_DATA(400, "Invalid request data"),
    INVALID_JSON_FORMAT(400, "Invalid json format"),
    INTERNAL_SERVER_ERROR(500,  "Internal Server Error"),
    DATA_TOO_SHORT(409, "data length too short!"),
    DATA_TOO_LONG(409, "data length too long!"),
    CONFLICT(409, "Conflict"),
    ENCRYPT_COLON_CONFLICT(409, "If the parameter contains ':', it will affect decryption."),
    DECRYPT_COLON_CONFLICT(409, "If the parameter too many ':', it will affect decryption."),

    ;

    private final int value;
    private final String reasonPhrase;

    CustomHttpStatus(int value, String reasonPhrase) {
        this.value = value;
        this.reasonPhrase = reasonPhrase;
    }

    @Override
    public int value() {
        return value;
    }

    @Override
    public String getReasonPhrase() {
        return reasonPhrase;
    }
}
