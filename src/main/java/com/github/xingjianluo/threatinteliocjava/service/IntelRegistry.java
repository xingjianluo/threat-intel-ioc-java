package com.github.xingjianluo.threatinteliocjava.service;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 当前生效情报的持有者：AtomicReference 指向不可变快照。
 * 启动时尚未刷新时为空；刷新失败永远不清空，保证上一份已知良好结果继续可用。
 */
@Component
public class IntelRegistry {

    private final AtomicReference<IntelSnapshot> current = new AtomicReference<>();

    public Optional<IntelSnapshot> currentSnapshot() {
        return Optional.ofNullable(current.get());
    }

    public void publish(IntelSnapshot snapshot) {
        current.set(snapshot);
    }
}
