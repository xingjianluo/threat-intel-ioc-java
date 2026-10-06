package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.Caller;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshOutcome;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖规则解释测试：
 * 1) 被抑制/白名单规则圈住、但本身没有命中任何指标的查询 -> COVERED，
 *    结论体现"被规则覆盖"，但不是真正的命中（matched=false）；
 * 2) 覆盖判定给出规则 id 与原因；
 * 3) 覆盖/命中判定不因调用方权限不足而改变；
 * 4) 既未命中也未被覆盖 -> CLEAN；命中且被抑制 -> SUPPRESSED（优先级不变）。
 */
class CoverageExplainTest {

    private static final String FEEDS = "src/test/resources/data/feeds";
    private static final String SUP = "src/test/resources/data/suppressions.jsonl";
    private static final String CALLERS = "src/test/resources/data/callers.json";

    private ThreatIntelService service;
    private CallerDirectory directory;

    @BeforeEach
    void setUp() {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        directory = new CallerDirectory(repo);
        directory.load(CALLERS);
        service = new ThreatIntelService(repo, normalizer,
                new MatchEngine(normalizer), new AccessControlService(directory));
        RefreshOutcome outcome = service.refresh(FEEDS, SUP,
                Set.of("vendorB"), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());
    }

    @Test
    void coveredButNotMatchedIsCoveredDecisionNotAHit() {
        // 10.9.9.9 落在 SUP-1002 (10.0.0.0/8) 白名单内，但没有任何指标命中它
        Verdict v = service.match("ip", "10.9.9.9", null);
        assertEquals("COVERED", v.decision());
        assertFalse(v.matched(), "covered-but-not-hit must not be treated as a real hit");
        assertFalse(v.suppressed());
        assertTrue(v.covered());
        assertTrue(v.matchedKeys().isEmpty());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("SUP-1002")),
                "reasons must cite the covering rule id: " + v.reasons());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("internal network allowlist")),
                "reasons must cite the rule reason: " + v.reasons());
    }

    @Test
    void coveredUrlHostWithoutIndicatorHitIsCovered() {
        // URL 主机落在网段白名单内，但无 URL/网段指标命中
        Verdict v = service.match("url", "http://10.9.9.9/path", null);
        assertEquals("COVERED", v.decision());
        assertFalse(v.matched());
        assertTrue(v.covered());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("SUP-1002")));
    }

    @Test
    void notMatchedAndNotCoveredIsClean() {
        Verdict v = service.match("ip", "203.0.113.99", null);
        assertEquals("CLEAN", v.decision());
        assertFalse(v.matched());
        assertFalse(v.covered());
    }

    @Test
    void matchedAndSuppressedKeepsSuppressedPrecedence() {
        // 命中指标且被规则覆盖：仍是 SUPPRESSED，不是 COVERED
        Verdict v = service.match("ip", "10.1.2.3", null);
        assertEquals("SUPPRESSED", v.decision());
        assertTrue(v.matched());
        assertTrue(v.suppressed());
        assertFalse(v.covered());
    }

    @Test
    void coverageVerdictIsIdenticalAcrossCallerPrivileges() {
        Caller viewer = directory.resolve("viewer-key");
        Caller analyst = directory.resolve("analyst-key");
        for (Caller caller : new Caller[]{null, viewer, analyst}) {
            Verdict v = service.match("ip", "10.9.9.9", caller);
            assertEquals("COVERED", v.decision(),
                    "caller privileges must not change coverage decision");
            assertFalse(v.matched());
            assertTrue(v.covered());
        }
        // 命中判定同样不受权限影响（受限来源指标）
        for (Caller caller : new Caller[]{null, viewer, analyst}) {
            Verdict v = service.match(null, "restricted.internal", caller);
            assertEquals("HIT", v.decision());
            assertTrue(v.matched());
        }
    }
}
