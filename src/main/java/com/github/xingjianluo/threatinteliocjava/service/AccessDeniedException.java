package com.github.xingjianluo.threatinteliocjava.service;

/** 调用方角色不满足指标明细的访问要求。 */
public class AccessDeniedException extends RuntimeException {
    public AccessDeniedException(String message) {
        super(message);
    }
}
