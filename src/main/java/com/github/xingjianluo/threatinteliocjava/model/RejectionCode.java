package com.github.xingjianluo.threatinteliocjava.model;

/**
 * 条目不被接受的可区分原因。
 */
public enum RejectionCode {
    MALFORMED_FORMAT,
    UNSUPPORTED_TYPE,
    INVALID_VALUE,
    PARSE_IO_ERROR,
    CONFLICT_REJECTED
}
