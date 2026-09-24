package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.Indicator;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 导入链路测试：
 * 1) 畸形/不支持类型条目按可区分原因拒绝，FAIL_CLOSED 整批保留旧状态；
 * 2) 冲突严重度按确定规则收敛为最高且留痕；
 * 3) 相同内容重复刷新版本不递增、无重复计数与漂移；
 * 4) ACCEPT_PARTIAL 下坏条目记录、好条目生效。
 */
class ThreatIntelIngestionTest {

    private static final String FEEDS = "src/test/resources/data/feeds";
    private static final String MALFORMED = "src/test/resources/data/malformed-feeds";
    private static final String CONFLICT = "src/test/resources/data/conflict-feeds";
    private static final String SUP = "src/test/resources/data/suppressions.jsonl";

    private ThreatIntelService service;

    @BeforeEach
    void setUp() {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        CallerDirectory directory = new CallerDirectory(repo);
        directory.loadBuiltinFallback();
        AccessControlService access = new AccessControlService(directory);
        MatchEngine engine = new MatchEngine(normalizer);
        service = new ThreatIntelService(repo, normalizer, engine, access);
    }

    @Test
    void firstCleanLoadAppliesWithDeterministicCounts() {
        RefreshOutcome outcome = service.refresh(FEEDS, SUP, Set.of("vendorB"),
                RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());
        assertEquals(1, outcome.version());
        assertFalse(outcome.report().hasRejections());
        // 两种格式均被导入；vendorA 中有一对等价 IP 混淆写法（同一指标去重）
        assertEquals(2, service.currentSnapshot().sourceCounts().size());
        assertTrue(service.currentSnapshot().sourceCounts().get("vendorA") >= 9);
        assertEquals(2, service.currentSnapshot().suppressions().size());
    }

    @Test
    void malformedEntriesFailClosedAndAreDistinguishable() {
        // 先装一份良好快照
        RefreshOutcome good = service.refresh(FEEDS, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", good.outcome());
        int goodCount = service.currentSnapshot().indicators().size();

        RefreshOutcome bad = service.refresh(MALFORMED, "missing.jsonl", Set.of(),
                RefreshPolicy.FAIL_CLOSED);
        assertEquals("REJECTED_PRESERVED", bad.outcome());
        // 原有良好状态完整保留
        assertEquals(1, service.currentSnapshot().version());
        assertEquals(goodCount, service.currentSnapshot().indicators().size());
        // 拒绝原因可区分：INVALID_VALUE / UNSUPPORTED_TYPE / MALFORMED_FORMAT
        List<RejectionCode> codes = bad.failures().stream().map(f -> f.code()).toList();
        assertTrue(codes.contains(RejectionCode.INVALID_VALUE), "expected INVALID_VALUE: " + codes);
        assertTrue(codes.contains(RejectionCode.UNSUPPORTED_TYPE),
                "expected UNSUPPORTED_TYPE: " + codes);
        assertTrue(codes.contains(RejectionCode.MALFORMED_FORMAT),
                "expected MALFORMED_FORMAT: " + codes);
    }

    @Test
    void firstLoadWithMalformedEntriesHasNoPreviousState() {
        RefreshOutcome bad = service.refresh(MALFORMED, "missing.jsonl", Set.of(),
                RefreshPolicy.FAIL_CLOSED);
        assertEquals("REJECTED_NO_PREVIOUS_STATE", bad.outcome());
        assertEquals(0, service.currentSnapshot().version());
        assertTrue(service.currentSnapshot().indicators().isEmpty());
    }

    @Test
    void acceptPartialRecordsRejectionsAndAppliesGoodEntries() {
        RefreshOutcome outcome = service.refresh(MALFORMED, "missing.jsonl", Set.of(),
                RefreshPolicy.ACCEPT_PARTIAL);
        assertEquals("APPLIED_PARTIAL", outcome.outcome());
        assertTrue(outcome.report().hasRejections());
        // bad.jsonl 中 8.8.8.8 是唯一好条目
        assertTrue(service.currentSnapshot().indicators().stream()
                .anyMatch(i -> i.value().equals("8.8.8.8")));
    }

    @Test
    void conflictingSeverityConvergesToHighestWithNote() {
        RefreshOutcome outcome = service.refresh(CONFLICT, "missing.jsonl", Set.of(),
                RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());
        // 同一 IP 三种严重度（LOW/CRITICAL/HIGH）只产生一个指标，且收敛为 CRITICAL
        Indicator ip = service.currentSnapshot().indicators().stream()
                .filter(i -> i.value().equals("1.2.3.4")).findFirst().orElseThrow();
        assertEquals("CRITICAL", ip.severity().name());
        assertNotNull(ip.conflictNote());
        assertTrue(ip.conflictNote().contains("severity"));
        // 域名跨大小写写法也只产生一个指标，HIGH > MEDIUM
        Indicator domain = service.currentSnapshot().indicators().stream()
                .filter(i -> i.value().equals("conflict.example")).findFirst().orElseThrow();
        assertEquals("HIGH", domain.severity().name());
        // 去重计数：原始 5 条 -> 2 个唯一指标，3 条重复
        assertEquals(2, outcome.report().accepted());
        assertEquals(3, outcome.report().duplicates());
        assertEquals(2, outcome.report().mergedConflicts());
        // 来源取并集
        assertEquals(Set.of("c"), ip.sources());
    }

    @Test
    void repeatedRefreshOfSameContentIsIdempotentAndVersionStable() {
        RefreshOutcome first = service.refresh(FEEDS, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        String hash = service.currentSnapshot().contentHash();
        RefreshOutcome second = service.refresh(FEEDS, SUP, Set.of(), RefreshPolicy.FAIL_CLOSED);
        RefreshOutcome third = service.refresh(FEEDS, SUP, Set.of(), RefreshPolicy.ACCEPT_PARTIAL);
        assertEquals("APPLIED_UNCHANGED", second.outcome());
        assertEquals("APPLIED_UNCHANGED", third.outcome());
        assertEquals(1, service.currentSnapshot().version());
        assertEquals(hash, service.currentSnapshot().contentHash());
        // 指标数量无重复
        long keys = service.currentSnapshot().indicators().stream().map(Indicator::key).count();
        long distinct = service.currentSnapshot().indicators().stream().map(Indicator::key).distinct().count();
        assertEquals(keys, distinct);
    }
}
