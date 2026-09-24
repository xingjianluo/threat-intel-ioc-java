package com.github.xingjianluo.threatinteliocjava.web;

import com.github.xingjianluo.threatinteliocjava.access.AccessDeniedException;
import com.github.xingjianluo.threatinteliocjava.normalize.NormalizationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * 统一错误响应：403（权限不足）、400（输入不合法）、401（未知凭据）可区分。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleDenied(AccessDeniedException ex) {
        log.warn("403 access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error", "ACCESS_DENIED",
                "caller", ex.callerId(),
                "source", ex.source(),
                "message", ex.getMessage()));
    }

    @ExceptionHandler(NormalizationException.class)
    public ResponseEntity<Map<String, Object>> handleNormalization(NormalizationException ex) {
        log.warn("400 bad indicator input: code={} message={}", ex.code(), ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of(
                "error", "INVALID_INDICATOR",
                "reasonCode", ex.code().name(),
                "message", ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegal(IllegalArgumentException ex) {
        log.warn("400 illegal argument: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of(
                "error", "BAD_REQUEST",
                "message", String.valueOf(ex.getMessage())));
    }
}
