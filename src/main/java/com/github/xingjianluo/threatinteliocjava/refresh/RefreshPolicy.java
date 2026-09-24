package com.github.xingjianluo.threatinteliocjava.refresh;

/**
 * 刷新失败处理策略。
 * FAIL_CLOSED（默认）：存在任何拒绝/失败条目则整批不生效，保留上一份良好快照。
 * ACCEPT_PARTIAL：拒绝条目逐条记录，其余好条目生效（首装同样允许部分生效）。
 */
public enum RefreshPolicy {
    FAIL_CLOSED,
    ACCEPT_PARTIAL
}
