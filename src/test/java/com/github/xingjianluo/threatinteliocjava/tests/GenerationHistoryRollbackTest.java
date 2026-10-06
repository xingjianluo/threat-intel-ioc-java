package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.ThreatSnapshot;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import com.github.xingjianluo.threatinteliocjava.refresh.GenerationNotFoundException;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.RollbackOutcome;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 代际查询与回滚测试：
 * 1) 匹配既可看最新一代，也可指定历史代；
 * 2) 回滚把当前生效结果切回历史代，被替换的代重新进入历史；
 * 3) 历史容量有限（可配置），被淘汰的代不可查询、不可回滚，淘汰不影响当前生效代；
 * 4) 回滚与查询并发时，每个判定都落在完整的一代上。
 */
class GenerationHistoryRollbackTest {

    @TempDir
    Path tempDir;

    private ThreatIntelService newService(int historyCapacity) {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        CallerDirectory directory = new CallerDirectory(repo);
        directory.loadBuiltinFallback();
        return new ThreatIntelService(repo, normalizer,
                new MatchEngine(normalizer), new AccessControlService(directory),
                historyCapacity);
    }

    /** 造一个只含单个域名指标的目录（目录名即来源名前缀不同，保证内容哈希不同）。 */
    private Path dirWith(String name, String domain) throws IOException {
        Path dir = Files.createDirectory(tempDir.resolve(name));
        Files.writeString(dir.resolve("feed-" + name + ".jsonl"),
                "{\"type\":\"domain\",\"value\":\"" + domain + "\",\"severity\":\"high\"}\n");
        return dir;
    }

    private long refresh(ThreatIntelService service, Path dir) {
        var outcome = service.refresh(dir.toString(), "missing-sup.jsonl",
                Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());
        return outcome.version();
    }

    @Test
    void matchCanTargetLatestOrSpecificGeneration() throws Exception {
        ThreatIntelService service = newService(5);
        long v1 = refresh(service, dirWith("a", "evil-a.example"));
        long v2 = refresh(service, dirWith("b", "evil-b.example"));
        assertEquals(1, v1);
        assertEquals(2, v2);

        // 默认看最新一代
        assertEquals("CLEAN", service.match("domain", "evil-a.example", null).decision());
        assertEquals("HIT", service.match("domain", "evil-b.example", null).decision());
        // 指定历史代
        assertEquals("HIT", service.match("domain", "evil-a.example", null, v1).decision());
        assertEquals("CLEAN", service.match("domain", "evil-b.example", null, v1).decision());
        // 显式指定当前代与默认一致
        assertEquals("HIT", service.match("domain", "evil-b.example", null, v2).decision());

        // 代际列表可追溯：v1 历史 + v2 生效
        List<ThreatSnapshot> generations = service.generations();
        assertEquals(List.of(v1, v2),
                generations.stream().map(ThreatSnapshot::version).toList());
    }

    @Test
    void rollbackSwapsActiveGenerationAndKeepsItTraceable() throws Exception {
        ThreatIntelService service = newService(5);
        long v1 = refresh(service, dirWith("a", "evil-a.example"));
        long v2 = refresh(service, dirWith("b", "evil-b.example"));

        RollbackOutcome rolled = service.rollback(v1);
        assertEquals("ROLLED_BACK", rolled.outcome());
        assertEquals(v1, rolled.version());
        // 当前生效结果回到 v1 的内容
        assertEquals("HIT", service.match("domain", "evil-a.example", null).decision());
        assertEquals("CLEAN", service.match("domain", "evil-b.example", null).decision());
        // 被替换的 v2 进入历史，仍可按代查询
        assertEquals("HIT", service.match("domain", "evil-b.example", null, v2).decision());

        // 回滚到当前代是明确的无操作结论
        RollbackOutcome same = service.rollback(v1);
        assertEquals("ALREADY_CURRENT", same.outcome());

        // 还能再滚回 v2
        RollbackOutcome forward = service.rollback(v2);
        assertEquals("ROLLED_BACK", forward.outcome());
        assertEquals("HIT", service.match("domain", "evil-b.example", null).decision());
    }

    @Test
    void evictedGenerationsCannotBeQueriedOrRolledBack() throws Exception {
        ThreatIntelService service = newService(2); // 只保留最近 2 代历史
        long v1 = refresh(service, dirWith("a", "evil-a.example"));
        refresh(service, dirWith("b", "evil-b.example"));
        long v3 = refresh(service, dirWith("c", "evil-c.example"));
        long v4 = refresh(service, dirWith("d", "evil-d.example"));

        // 容量 2：历史只留 v2、v3；v1 已被淘汰
        assertEquals(List.of(2L, 3L, 4L),
                service.generations().stream().map(ThreatSnapshot::version).toList());

        // 被淘汰的代：回滚与查询都被明确拒绝，且原因可区分
        RollbackOutcome evicted = service.rollback(v1);
        assertEquals("GENERATION_EVICTED", evicted.outcome());
        assertEquals(v4, evicted.version(), "rejected rollback must not change active generation");
        GenerationNotFoundException ex = assertThrows(GenerationNotFoundException.class,
                () -> service.match("domain", "evil-a.example", null, v1));
        assertEquals("GENERATION_EVICTED", ex.reason());

        // 从未存在过的代：原因不同
        assertEquals("GENERATION_NOT_FOUND", service.rollback(99L).outcome());
        assertEquals("GENERATION_NOT_FOUND", assertThrows(GenerationNotFoundException.class,
                () -> service.match("domain", "x.example", null, 99L)).reason());

        // 淘汰不影响当前生效代，也不影响仍在容量内的历史代
        assertEquals("HIT", service.match("domain", "evil-d.example", null).decision());
        assertEquals("HIT", service.match("domain", "evil-c.example", null, v3).decision());
    }

    @Test
    void concurrentRollbackAndQueriesAlwaysSeeCompleteGenerations() throws Exception {
        ThreatIntelService service = newService(5);
        long v1 = refresh(service, dirWith("a", "evil-a.example"));
        long v2 = refresh(service, dirWith("b", "evil-b.example"));

        int queryThreads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(queryThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicBoolean rollbackerDone = new AtomicBoolean(false);
        AtomicInteger errors = new AtomicInteger();
        ConcurrentLinkedQueue<String> violations = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new java.util.ArrayList<>();

        // 查询线程：指定代的查询结果必须永远对应该代的完整内容
        for (int t = 0; t < queryThreads; t++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    while (!rollbackerDone.get()) {
                        Verdict g1a = service.match("domain", "evil-a.example", null, v1);
                        Verdict g1b = service.match("domain", "evil-b.example", null, v1);
                        Verdict g2b = service.match("domain", "evil-b.example", null, v2);
                        Verdict latest = service.match("domain", "evil-a.example", null);
                        if (!"HIT".equals(g1a.decision())) {
                            violations.add("v1 must always hit evil-a: " + g1a.decision());
                        }
                        if (!"CLEAN".equals(g1b.decision())) {
                            violations.add("v1 must never contain evil-b: " + g1b.decision());
                        }
                        if (!"HIT".equals(g2b.decision())) {
                            violations.add("v2 must always hit evil-b: " + g2b.decision());
                        }
                        if (!"HIT".equals(latest.decision()) && !"CLEAN".equals(latest.decision())) {
                            violations.add("latest must be a complete generation: " + latest.decision());
                        }
                    }
                } catch (Throwable e) {
                    errors.incrementAndGet();
                    violations.add("EX: " + e);
                }
            }));
        }
        // 回滚线程：在 v1/v2 之间反复切换当前生效代
        futures.add(pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < 300; i++) {
                    RollbackOutcome o = service.rollback(i % 2 == 0 ? v1 : v2);
                    if (!"ROLLED_BACK".equals(o.outcome()) && !"ALREADY_CURRENT".equals(o.outcome())) {
                        violations.add("unexpected rollback outcome: " + o.outcome());
                    }
                }
            } catch (Throwable e) {
                errors.incrementAndGet();
                violations.add("EX-ROLLBACK: " + e);
            } finally {
                rollbackerDone.set(true);
            }
        }));
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS), "test did not finish in time");
        for (Future<?> f : futures) {
            f.get(5, TimeUnit.SECONDS);
        }
        assertEquals(0, errors.get());
        assertTrue(violations.isEmpty(), "concurrent rollback/query violations: " + violations);
        // 两代都始终可用（容量足够），最终生效代是其中之一且完整
        assertTrue(service.currentSnapshot().version() == v1
                || service.currentSnapshot().version() == v2);
    }
}
