package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.FeedParseException;
import com.github.xingjianluo.threatinteliocjava.ingest.FeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.ParsedBatch;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.Generation;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import com.github.xingjianluo.threatinteliocjava.model.SourceDisposition;
import com.github.xingjianluo.threatinteliocjava.model.SourceHealth;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import com.github.xingjianluo.threatinteliocjava.refresh.GenerationHistory;
import com.github.xingjianluo.threatinteliocjava.refresh.GenerationNotFoundException;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshOutcome;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 代际治理测试：
 * 1) 每次成功刷新形成一代，来源健康区分 正常采用 / 合法为空 / 读取失败；
 * 2) 来源读取失败时匹配继续按上一代判定，且刷新结论明确为未成功；
 * 3) 按代查询与回滚；回滚原子切换，并发查询只看到完整的一代；
 * 4) 容量淘汰不影响当前生效代，被淘汰的代际不可查询也不可回滚。
 */
class GenerationGovernanceTest {

    private static final String SUP = "src/test/resources/data/suppressions.jsonl";

    @TempDir
    Path tempDir;

    private Normalizer normalizer;
    private LocalFeedRepository repository;

    /** 模拟"来源暂时不可用"的解析器：对 .boom 文件一律抛文件级读取异常。 */
    private static final class OutageParser implements FeedParser {
        @Override
        public String supportedExtension() {
            return ".boom";
        }

        @Override
        public ParsedBatch parse(String content) {
            throw new FeedParseException(RejectionCode.PARSE_IO_ERROR,
                    "simulated source outage: feed not readable this round");
        }
    }

    @BeforeEach
    void setUp() {
        normalizer = new Normalizer();
        repository = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser(), new OutageParser()));
    }

    private ThreatIntelService newService(int capacity) {
        CallerDirectory directory = new CallerDirectory(repository);
        directory.loadBuiltinFallback();
        return new ThreatIntelService(repository, normalizer,
                new MatchEngine(normalizer), new AccessControlService(directory),
                new GenerationHistory(capacity));
    }

    /** 造一个情报目录：sourceName -> 文件内容（jsonl 行）。 */
    private String feedDir(String name, Map<String, String> files) throws IOException {
        Path dir = tempDir.resolve(name);
        Files.createDirectories(dir);
        for (Map.Entry<String, String> f : files.entrySet()) {
            Files.writeString(dir.resolve(f.getKey()), f.getValue());
        }
        return dir.toString();
    }

    private static Map<String, SourceDisposition> bySource(Generation g) {
        return g.sources().stream().collect(Collectors.toMap(
                SourceDisposition::source, Function.identity()));
    }

    // ------------------------------------------------------------------
    // 1) 来源健康：正常采用 / 合法为空 / 读取失败 可区分
    // ------------------------------------------------------------------

    @Test
    void sourceHealthDistinguishesAdoptedLegitEmptyAndUnreadable() throws Exception {
        ThreatIntelService service = newService(5);
        String dir = feedDir("mixed", Map.of(
                "good.jsonl", "{\"type\":\"domain\",\"value\":\"evil-a.example\"}\n",
                "quiet.jsonl", "",
                "broken.boom", "irrelevant\n"));

        RefreshOutcome outcome = service.refresh(dir, SUP, Set.of(),
                RefreshPolicy.ACCEPT_PARTIAL);
        assertEquals("APPLIED_PARTIAL", outcome.outcome(),
                "unreadable source must make the refresh explicitly not fully successful");
        assertFalse(outcome.failures().isEmpty());

        Generation g = service.currentGeneration();
        assertNotNull(g);
        assertFalse(g.complete(), "generation with an unreadable source is not complete");
        Map<String, SourceDisposition> bySource = bySource(g);
        assertEquals(SourceHealth.ADOPTED, bySource.get("good").health());
        assertEquals(SourceHealth.SKIPPED_EMPTY, bySource.get("quiet").health(),
                "legitimately empty source must be marked SKIPPED_EMPTY");
        assertEquals(SourceHealth.SKIPPED_UNREADABLE, bySource.get("broken").health(),
                "unreadable source must be marked SKIPPED_UNREADABLE, not empty");
        assertTrue(bySource.get("broken").detail().contains("PARSE_IO_ERROR"));

        // 合法空来源不等于异常：好来源的指标照常生效
        assertEquals("HIT", service.match(null, "evil-a.example", null).decision());
        // 最近刷新结论可追溯且明确为"未完全成功"
        assertEquals("APPLIED_PARTIAL", service.lastRefresh().outcome());
    }

    @Test
    void unreadableSourceFailsClosedAndMatchingStaysOnPreviousGeneration() throws Exception {
        ThreatIntelService service = newService(5);
        String goodDir = feedDir("good", Map.of(
                "vendorA.jsonl", "{\"type\":\"domain\",\"value\":\"evil-a.example\"}\n"));
        RefreshOutcome first = service.refresh(goodDir, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", first.outcome());
        assertTrue(service.currentGeneration().complete());

        // 来源这次读不到：FAIL_CLOSED 整批拒绝，匹配仍按上一代完整结果判定
        String degradedDir = feedDir("degraded", Map.of(
                "vendorA.jsonl", "{\"type\":\"domain\",\"value\":\"evil-a.example\"}\n",
                "vendorB.boom", "x\n"));
        RefreshOutcome failed = service.refresh(degradedDir, SUP, Set.of(),
                RefreshPolicy.FAIL_CLOSED);
        assertEquals("REJECTED_PRESERVED", failed.outcome(),
                "read failure must be an explicit unsuccessful outcome, not an empty feed");
        assertEquals(1, service.currentSnapshot().version(), "no new generation on failure");
        assertEquals(1, service.generations().size());
        assertEquals("HIT", service.match(null, "evil-a.example", null).decision());
        assertEquals("REJECTED_PRESERVED", service.lastRefresh().outcome());

        // 对照：来源合法为空是正常一代，不是异常
        String emptyDir = feedDir("empty", Map.of("vendorA.jsonl", ""));
        RefreshOutcome emptied = service.refresh(emptyDir, SUP, Set.of(),
                RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", emptied.outcome());
        Generation g2 = service.currentGeneration();
        assertTrue(g2.complete(), "legitimately empty sources still form a complete generation");
        assertEquals(SourceHealth.SKIPPED_EMPTY, bySource(g2).get("vendorA").health());
        assertEquals("CLEAN", service.match(null, "evil-a.example", null).decision());
    }

    // ------------------------------------------------------------------
    // 2) 按代查询与回滚
    // ------------------------------------------------------------------

    @Test
    void matchCanTargetSpecificGenerationAndRollbackSwitchesCurrent() throws Exception {
        ThreatIntelService service = newService(5);
        String dirA = feedDir("genA", Map.of(
                "vendorA.jsonl", "{\"type\":\"domain\",\"value\":\"evil-a.example\"}\n"));
        String dirB = feedDir("genB", Map.of(
                "vendorA.jsonl", "{\"type\":\"domain\",\"value\":\"evil-b.example\"}\n"));
        service.refresh(dirA, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        service.refresh(dirB, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals(2, service.currentSnapshot().version());

        // 最新一代只看 gen2 的内容
        assertEquals("CLEAN", service.match(null, "evil-a.example", null).decision());
        assertEquals("HIT", service.match(null, "evil-b.example", null).decision());
        // 指定看历史第一代
        assertEquals("HIT", service.match(null, "evil-a.example", null, 1L).decision());
        assertEquals("CLEAN", service.match(null, "evil-b.example", null, 1L).decision());
        // 从未存在的代际
        assertThrows(GenerationNotFoundException.class,
                () -> service.match(null, "evil-a.example", null, 99L));

        // 回滚到第一代：当前生效结果整体切换
        Generation rolled = service.rollback(1L);
        assertEquals(1L, rolled.id());
        assertEquals("HIT", service.match(null, "evil-a.example", null).decision());
        assertEquals("CLEAN", service.match(null, "evil-b.example", null).decision());
        assertEquals(1L, service.currentGeneration().id());
        // 回滚不删除历史：第二代仍可查询、可再回滚
        assertEquals("HIT", service.match(null, "evil-b.example", null, 2L).decision());
        service.rollback(2L);
        assertEquals("HIT", service.match(null, "evil-b.example", null).decision());
    }

    // ------------------------------------------------------------------
    // 3) 容量淘汰：不影响当前生效代；被淘汰代不可查询/回滚
    // ------------------------------------------------------------------

    @Test
    void evictionRespectsCapacityAndEvictedGenerationsAreUnusable() throws Exception {
        ThreatIntelService service = newService(2);
        for (int i = 1; i <= 4; i++) {
            String dir = feedDir("gen" + i, Map.of("vendorA.jsonl",
                    "{\"type\":\"domain\",\"value\":\"evil-" + i + ".example\"}\n"));
            RefreshOutcome o = service.refresh(dir, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
            assertEquals("APPLIED", o.outcome());
        }
        // 容量 2：只保留最近两代，当前生效的是第 4 代
        assertEquals(List.of(4L, 3L),
                service.generations().stream().map(Generation::id).toList());
        assertEquals(4L, service.currentGeneration().id());
        assertEquals("HIT", service.match(null, "evil-4.example", null).decision());

        // 被淘汰的第 1/2 代：不可查询、不可回滚
        assertThrows(GenerationNotFoundException.class,
                () -> service.match(null, "evil-1.example", null, 1L));
        assertThrows(GenerationNotFoundException.class, () -> service.rollback(2L));

        // 回滚到仍保留的第 3 代后，再发布新一代：当前生效结果切换为第 5 代，
        // 淘汰只动最旧的非当前代（第 3 代让位），当前生效的第 5 代不受影响
        service.rollback(3L);
        String dir5 = feedDir("gen5", Map.of("vendorA.jsonl",
                "{\"type\":\"domain\",\"value\":\"evil-5.example\"}\n"));
        service.refresh(dir5, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals(List.of(5L, 4L),
                service.generations().stream().map(Generation::id).toList(),
                "eviction must only drop oldest non-current generations");
        assertEquals(5L, service.currentGeneration().id());
        assertEquals("HIT", service.match(null, "evil-5.example", null).decision());
        // 第 3 代已被淘汰，不能再被当成可用结果回滚或查询
        assertThrows(GenerationNotFoundException.class, () -> service.rollback(3L));
        assertThrows(GenerationNotFoundException.class,
                () -> service.match(null, "evil-3.example", null, 3L));
        // 回滚后再刷新版本号不复用：第 5 代不是重新编号出来的 4
        assertEquals(5, service.currentSnapshot().version());
    }

    // ------------------------------------------------------------------
    // 4) 并发回滚与查询：只能看到完整的一代
    // ------------------------------------------------------------------

    @Test
    void concurrentRollbackAndQueriesNeverSeeHalfGenerations() throws Exception {
        ThreatIntelService service = newService(5);
        // 第 1 代只有 A；第 2 代含两个会被同一次查询同时命中的指标
        // （域指标 + 同主机 URL 指标），单次判定的 matchedKeys 要么 0 个要么 2 个，
        // 出现 1 个即说明看到了"半代"状态
        String dir1 = feedDir("full1", Map.of("vendorA.jsonl",
                "{\"type\":\"domain\",\"value\":\"full-a.example\"}\n"));
        String dir2 = feedDir("full2", Map.of("vendorA.jsonl", """
                {"type":"domain","value":"full-a.example"}
                {"type":"domain","value":"multi.example"}
                {"type":"url","value":"http://multi.example/path"}
                """));
        service.refresh(dir1, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        service.refresh(dir2, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);

        int queryThreads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(queryThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicBoolean togglerDone = new AtomicBoolean(false);
        ConcurrentLinkedQueue<String> inconsistencies = new ConcurrentLinkedQueue<>();

        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < queryThreads; t++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    while (!togglerDone.get()) {
                        Verdict a = service.match(null, "full-a.example", null);
                        Verdict multi = service.match(null, "multi.example", null);
                        // A 两代都命中；单次判定内两个指标必须同生共死
                        if (!"HIT".equals(a.decision())) {
                            inconsistencies.add("A must always HIT, got " + a.decision());
                        }
                        int keys = multi.matchedKeys().size();
                        if (keys != 0 && keys != 2) {
                            inconsistencies.add("half generation observed: matchedKeys="
                                    + multi.matchedKeys() + " decision=" + multi.decision());
                        }
                        if (keys == 0 && !"CLEAN".equals(multi.decision())) {
                            inconsistencies.add("gen1 view must be CLEAN, got "
                                    + multi.decision());
                        }
                        if (keys == 2 && !"HIT".equals(multi.decision())) {
                            inconsistencies.add("gen2 view must be HIT, got "
                                    + multi.decision());
                        }
                    }
                } catch (Throwable e) {
                    inconsistencies.add("EX: " + e);
                }
            }));
        }
        futures.add(pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < 300; i++) {
                    service.rollback(i % 2 == 0 ? 1L : 2L);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                inconsistencies.add("EX-TOGGLER: " + e);
            } finally {
                togglerDone.set(true);
            }
        }));
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        for (Future<?> f : futures) {
            f.get(5, TimeUnit.SECONDS);
        }
        assertTrue(inconsistencies.isEmpty(),
                "concurrent queries must only see whole generations: " + inconsistencies);
    }
}
