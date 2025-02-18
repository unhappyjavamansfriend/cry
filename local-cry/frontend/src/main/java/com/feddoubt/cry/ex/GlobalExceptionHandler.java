package com.feddoubt.cry.ex;

import com.feddoubt.common.config.message.ApiResponse;
import com.feddoubt.common.config.message.ResponseUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<ApiResponse<Object>> handleCustomException(CustomException e) {
        return ResponseUtils.handleCustomException(e.getStatusCode(), e.getReasonPhrase());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGeneralException(Exception e) {
        return ResponseUtils.handleCustomException(500, "Internal Server Error");
    }
}
