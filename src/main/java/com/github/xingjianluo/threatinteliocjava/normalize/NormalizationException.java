package com.github.xingjianluo.threatinteliocjava.normalize;

/** 归一失败：输入值无法解析为合法的指标值。 */
public class NormalizationException extends RuntimeException {
    public NormalizationException(String message) {
        super(message);
    }

    public NormalizationException(String message, Throwable cause) {
        super(message, cause);
    }
}
