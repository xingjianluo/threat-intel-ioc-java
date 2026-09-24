package com.github.xingjianluo.threatinteliocjava.service;

/** 查询的指标不存在。 */
public class IndicatorNotFoundException extends RuntimeException {
    public IndicatorNotFoundException(String message) {
        super(message);
    }
}
