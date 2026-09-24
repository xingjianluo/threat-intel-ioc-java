package com.github.xingjianluo.threatinteliocjava.ingest;

import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;

/**
 * 文件级格式/IO 错误（如错误的 CSV 表头、不可读文件）。
 * 逐行的坏条目以 {@link RejectedEntry} 返回，不使用本异常。
 */
public class FeedParseException extends RuntimeException {

    private final RejectionCode code;

    public FeedParseException(RejectionCode code, String message) {
        super(message);
        this.code = code;
    }

    public FeedParseException(RejectionCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public RejectionCode code() {
        return code;
    }
}
