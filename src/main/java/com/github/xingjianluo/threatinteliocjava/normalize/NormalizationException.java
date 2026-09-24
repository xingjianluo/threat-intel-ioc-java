package com.github.xingjianluo.threatinteliocjava.normalize;

import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;

/**
 * 归一化失败，携带可区分的拒绝原因。
 */
public class NormalizationException extends RuntimeException {

    private final RejectionCode code;

    public NormalizationException(RejectionCode code, String message) {
        super(message);
        this.code = code;
    }

    public NormalizationException(RejectionCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public RejectionCode code() {
        return code;
    }
}
