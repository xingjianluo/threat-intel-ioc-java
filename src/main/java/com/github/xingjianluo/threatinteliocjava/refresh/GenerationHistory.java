package com.github.xingjianluo.threatinteliocjava.refresh;

import com.github.xingjianluo.threatinteliocjava.config.ThreatIntelProperties;
import com.github.xingjianluo.threatinteliocjava.model.Generation;
import com.github.xingjianluo.threatinteliocjava.model.SourceDisposition;
import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 容量有界的代际历史：保存最近 N 代（默认 5，可配置），
 * 支持按代查询与原子回滚。
 *
 * <p>一致性保证：
 * <ul>
 *   <li>{@code current} 为 volatile 引用，发布/回滚只整体替换引用，
 *       并发查询任意时刻只会看到完整的一代，绝不出现半新半旧。</li>
 *   <li>发布与回滚在内部锁下串行；淘汰只移除最旧的非当前代，
 *       当前生效代永远不会被淘汰。</li>
 *   <li>已被淘汰的代际从历史中移除，之后按代查询与回滚都会得到
 *       {@link GenerationNotFoundException}，不会被当成可用结果。</li>
 * </ul>
 */
@Component
public class GenerationHistory {

    private static final Logger log = LoggerFactory.getLogger(GenerationHistory.class);

    private final int capacity;
    /** 按代际编号升序（插入序）保留的代际；访问在锁下串行。 */
    private final Map<Long, Generation> retained = new LinkedHashMap<>();
    private final Object lock = new Object();
    /** 历史最高代际编号：单调递增，淘汰与回滚都不会使其回退，保证编号永不复用。 */
    private long highest;
    private volatile Generation current;

    @Autowired
    public GenerationHistory(ThreatIntelProperties properties) {
        this(properties.getGenerationHistoryCapacity());
    }

    public GenerationHistory(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("generation history capacity must be >= 1");
        }
        this.capacity = capacity;
    }

    public int capacity() {
        return capacity;
    }

    /** 发布新一代并使其生效；超出容量时淘汰最旧的非当前代。 */
    public Generation publish(ThreatSnapshot snapshot, List<SourceDisposition> sources) {
        Generation generation = new Generation(snapshot.version(), snapshot.loadedAt(),
                snapshot, sources);
        synchronized (lock) {
            retained.put(generation.id(), generation);
            highest = Math.max(highest, generation.id());
            current = generation;
            evictOverflow();
        }
        log.info("generation {} published (complete={}, sources={}), retained={}/{}",
                generation.id(), generation.complete(), sources.size(),
                retained.size(), capacity);
        return generation;
    }

    /** 当前生效的一代；从未发布过时为 null。 */
    public Generation current() {
        return current;
    }

    /** 历史最高代际编号（单调，淘汰/回滚不回退）；从未发布过时为 0。 */
    public long highestVersion() {
        synchronized (lock) {
            return highest;
        }
    }

    /** 按代际编号查询仍在保留期内的代。 */
    public Optional<Generation> find(long id) {
        synchronized (lock) {
            return Optional.ofNullable(retained.get(id));
        }
    }

    /**
     * 回滚到历史某一代：原子切换当前引用，并发查询只看到完整的一代。
     * 已被淘汰或从未存在的代际抛出 {@link GenerationNotFoundException}。
     */
    public Generation rollback(long id) {
        synchronized (lock) {
            Generation target = retained.get(id);
            if (target == null) {
                log.warn("rollback rejected: generation {} not retained (capacity={})",
                        id, capacity);
                throw new GenerationNotFoundException(id,
                        "generation " + id + " is not retained (evicted or never existed)");
            }
            current = target;
            log.info("rolled back to generation {} (complete={}, retained={}/{})",
                    id, target.complete(), retained.size(), capacity);
            return target;
        }
    }

    /** 保留中的全部代际（新的在前）。 */
    public List<Generation> list() {
        synchronized (lock) {
            List<Generation> all = new ArrayList<>(retained.values());
            List<Generation> newestFirst = new ArrayList<>(all.size());
            for (int i = all.size() - 1; i >= 0; i--) {
                newestFirst.add(all.get(i));
            }
            return List.copyOf(newestFirst);
        }
    }

    /** 淘汰最旧的非当前代，直到规模回到容量内。当前生效代永不淘汰。 */
    private void evictOverflow() {
        var it = retained.entrySet().iterator();
        while (retained.size() > capacity && it.hasNext()) {
            Map.Entry<Long, Generation> eldest = it.next();
            if (eldest.getKey() == current.id()) {
                continue;
            }
            it.remove();
            log.info("generation {} evicted (capacity={})", eldest.getKey(), capacity);
        }
    }
}
