package com.github.xingjianluo.threatinteliocjava.access;

/**
 * 明细查询权限不足。注意：仅影响明细访问，不影响匹配命中判定本身。
 */
public class AccessDeniedException extends RuntimeException {

    private final String callerId;
    private final String source;

    public AccessDeniedException(String callerId, String source) {
        super("caller=" + callerId + " denied access to restricted source=" + source);
        this.callerId = callerId;
        this.source = source;
    }

    public String callerId() {
        return callerId;
    }

    public String source() {
        return source;
    }
}
