package com.github.xingjianluo.threatinteliocjava.model;

/** 条目被拒绝的可区分原因。 */
public enum RejectionReason {
    /** 类型代码不在支持范围内 */
    UNSUPPORTED_INDICATOR_TYPE,
    /** 缺少必填字段 */
    MISSING_REQUIRED_FIELD,
    /** 字段值格式不合法（IP/网段/哈希/置信度等） */
    MALFORMED_VALUE,
    /** CSV 行结构不合法（列数不符等） */
    MALFORMED_LINE,
    /** 文件级解析失败（如 JSON 整体损坏） */
    PARSE_ERROR,
    /** 抑制规则本身不合法 */
    MALFORMED_SUPPRESSION_RULE
}
