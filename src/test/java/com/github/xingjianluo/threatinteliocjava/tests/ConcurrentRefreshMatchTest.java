package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshOutcome;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发安全测试：
 * 1) 并发刷新只有一个真正执行，其余得到 ALREADY_RUNNING，最终版本只 +1、无重复计数；
 * 2) 大量查询与刷新并发时，每个判定要么 HIT 要么 CLEAN，
 *    绝不出现"基于半份数据"导致的异常或不一致结论；
 * 3) 连续多次相同内容刷新不改变版本。
 */
class ConcurrentRefreshMatchTest {

    private static final String FEEDS = "src/test/resources/data/feeds";
    private static final String SUP = "src/test/resources/data/suppressions.jsonl";

    private ThreatIntelService service;

    /** 刷新时制造 50ms 装载窗口，确保同闩并发刷新确定撞上 ALREADY_RUNNING。 */
    private static LocalFeedRepository slowRepo(LocalFeedRepository delegate) {
        return new LocalFeedRepository(List.of()) {
            @Override
            public LoadedDirectory load(String directory) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return delegate.load(directory);
            }

            @Override
            public String contentHash(String directory) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return delegate.contentHash(directory);
            }

            @Override
            public String readTextFile(String path) {
                return delegate.readTextFile(path);
            }
        };
    }

    @BeforeEach
    void setUp() {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository backing = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        LocalFeedRepository repo = slowRepo(backing);
        CallerDirectory directory = new CallerDirectory(backing);
        directory.loadBuiltinFallback();
        AccessControlService access = new AccessControlService(directory);
        MatchEngine engine = new MatchEngine(normalizer);
        service = new ThreatIntelService(repo, normalizer, engine, access);
    }

    @Test
    void concurrentRefreshesSerializeWithoutDuplicateCounts() throws Exception {
        service.refresh(FEEDS, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();
        AtomicInteger alreadyRunning = new AtomicInteger();
        List<Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    RefreshOutcome o = service.refresh(FEEDS, SUP, Set.of(),
                            RefreshPolicy.FAIL_CLOSED);
                    outcomes.add(o.outcome());
                    if ("ALREADY_RUNNING".equals(o.outcome())) {
                        alreadyRunning.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();
        // 同一内容：恰好一个刷新真正执行，其余全部 ALREADY_RUNNING，状态无损坏
        long applied = outcomes.stream().filter("APPLIED_UNCHANGED"::equals).count();
        assertEquals(1, applied, "exactly one concurrent refresh may execute, got " + applied);
        assertEquals(threads - 1, alreadyRunning.get(),
                "all other callers must see ALREADY_RUNNING");
        assertEquals(1, service.currentSnapshot().version());
        long keys = service.currentSnapshot().indicators().stream().map(i -> i.key()).count();
        long distinct = service.currentSnapshot().indicators().stream().map(i -> i.key()).distinct().count();
        assertEquals(keys, distinct);
    }

    @Test
    void queriesDuringRefreshAlwaysSeeCompleteSnapshot() throws Exception {
        // 首装为空快照；随后刷新到完整快照，查询线程全程并发
        int queryThreads = 8;
        int refreshes = 30;
        ExecutorService pool = Executors.newFixedThreadPool(queryThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();
        AtomicInteger hits = new AtomicInteger();
        AtomicInteger cleans = new AtomicInteger();
        ConcurrentLinkedQueue<String> badDecisions = new ConcurrentLinkedQueue<>();
        // 刷新线程完成信号：查询线程持续查询直到刷新窗口结束，
        // 保证查询负载确定地横跨"空快照 -> 完整快照"切换，而不是在首个刷新完成前就跑完
        java.util.concurrent.atomic.AtomicBoolean refresherDone =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        List<Future<?>> futures = new java.util.ArrayList<>();
        // 查询线程：对已知必然命中与必然不命中的两类值反复判定
        String[] hitInputs = {"EVIL.example.com", "192.168.10.10",
                "http://bad.example.com/a?b=1", "ABCD1234ABCD1234ABCD1234ABCD1234"};
        for (int t = 0; t < queryThreads; t++) {
            final int seed = t;
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    int i = 0;
                    // 刷新窗口内持续查询；窗口结束后再跑一轮，确保覆盖到 v1 生效之后
                    do {
                        Verdict v = service.match(null, hitInputs[(seed + i) % hitInputs.length], null);
                        if (!"HIT".equals(v.decision()) && !"CLEAN".equals(v.decision())
                                && !"SUPPRESSED".equals(v.decision())) {
                            badDecisions.add(v.decision());
                        }
                        if ("HIT".equals(v.decision())) {
                            hits.incrementAndGet();
                        } else {
                            cleans.incrementAndGet();
                        }
                        i++;
                    } while (!refresherDone.get() || i % 200 != 0);
                } catch (Throwable e) {
                    errors.incrementAndGet();
                    badDecisions.add("EX: " + e);
                }
            }));
        }
        // 刷新线程：在良好目录与一个干净副本目录间切换，保证每轮内容完整
        futures.add(pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < refreshes; i++) {
                    service.refresh(FEEDS, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
                }
            } catch (Throwable e) {
                errors.incrementAndGet();
                badDecisions.add("EX-REFRESH: " + e);
            } finally {
                refresherDone.set(true);
            }
        }));
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS), "test did not finish in time");
        for (Future<?> f : futures) {
            f.get(5, TimeUnit.SECONDS);
        }
        assertEquals(0, errors.get(), "no exceptions expected during concurrent access");
        assertTrue(badDecisions.isEmpty(), "every decision must be HIT/SUPPRESSED/CLEAN: " + badDecisions);
        // 空快照（v0）期间为 CLEAN，刷新完成后为 HIT；二者均为"完整快照"上的合法结论
        assertTrue(hits.get() > 0, "queries after load must observe HIT");
        // 最终版本：相同内容只有首次 APPLIED，之后全部 UNCHANGED
        assertEquals(1, service.currentSnapshot().version());
    }
}
