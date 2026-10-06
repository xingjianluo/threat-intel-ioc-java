package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.Caller;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖规则解释测试：
 * 1) 命中且被抑制 -> SUPPRESSED（covered=true）；
 * 2) 被规则圈住但本身未命中 -> COVERED：结论体现覆盖，但不是真正的命中；
 * 3) 未命中且未被覆盖 -> CLEAN（covered=false）；
 * 4) 调用方权限不足不改变覆盖或命中的判定。
 */
class CoverageExplanationTest {

    private static final String FEEDS = "src/test/resources/data/feeds";
    private static final String SUP = "src/test/resources/data/suppressions.jsonl";
    private static final String CALLERS = "src/test/resources/data/callers.json";

    @TempDir
    Path tempDir;

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
        var outcome = service.refresh(FEEDS, SUP, Set.of("vendorB"), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());
    }

    @Test
    void matchedAndSuppressedStaysSuppressedAndCovered() {
        Verdict v = service.match("domain", "safe.example.com", null);
        assertEquals("SUPPRESSED", v.decision());
        assertTrue(v.matched());
        assertTrue(v.covered());
        assertEquals(List.of("SUP-1001"), v.coveringRuleIds());
    }

    @Test
    void coveredButNotMatchedYieldsCoveredDecisionNotAHit() {
        // 10.200.1.1 落在 SUP-1002 的 10.0.0.0/8 白名单网段内，但没有任何指标命中它
        Verdict v = service.match("ip", "10.200.1.1", null);
        assertEquals("COVERED", v.decision(), "covered-but-not-matched must be distinguishable");
        assertFalse(v.matched(), "COVERED is not a true hit");
        assertFalse(v.suppressed());
        assertTrue(v.covered());
        assertEquals(List.of("SUP-1002"), v.coveringRuleIds());
        assertTrue(v.matchedKeys().isEmpty());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("SUP-1002")
                        && r.contains("no indicator matched")),
                "reasons must explain coverage without a hit: " + v.reasons());
    }

    @Test
    void domainCoveredButNotMatchedIsExplained() throws IOException {
        // 自定义抑制规则覆盖 internal.example 全域，但情报里没有该域的指标
        Path sup = tempDir.resolve("sup.jsonl");
        Files.writeString(sup, "{\"id\":\"SUP-9\",\"type\":\"domain\",\"pattern\":"
                + "\"internal.example\",\"reason\":\"corp internal zone\"}\n");
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        CallerDirectory dir = new CallerDirectory(repo);
        dir.loadBuiltinFallback();
        ThreatIntelService fresh = new ThreatIntelService(repo, normalizer,
                new MatchEngine(normalizer), new AccessControlService(dir));
        assertEquals("APPLIED", fresh.refresh(FEEDS, sup.toString(),
                Set.of(), RefreshPolicy.FAIL_CLOSED).outcome());

        Verdict v = fresh.match("domain", "host.internal.example", null);
        assertEquals("COVERED", v.decision());
        assertFalse(v.matched());
        assertEquals(List.of("SUP-9"), v.coveringRuleIds());
    }

    @Test
    void notMatchedAndNotCoveredStaysClean() {
        Verdict v = service.match(null, "unknown.nobody.example", null);
        assertEquals("CLEAN", v.decision());
        assertFalse(v.covered());
        assertTrue(v.coveringRuleIds().isEmpty());
    }

    @Test
    void callerPermissionsNeverChangeCoverageOrHitDecisions() {
        Caller viewer = directory.resolve("viewer-key");
        Caller analyst = directory.resolve("analyst-key");
        // 覆盖判定：三种调用方完全一致
        for (String input : List.of("10.200.1.1", "restricted.internal", "safe.example.com")) {
            Verdict anonymous = service.match(null, input, null);
            Verdict asViewer = service.match(null, input, viewer);
            Verdict asAnalyst = service.match(null, input, analyst);
            assertEquals(anonymous.decision(), asViewer.decision(), "input=" + input);
            assertEquals(anonymous.decision(), asAnalyst.decision(), "input=" + input);
            assertEquals(anonymous.covered(), asViewer.covered(), "input=" + input);
            assertEquals(anonymous.coveringRuleIds(), asAnalyst.coveringRuleIds(),
                    "input=" + input);
        }
        // 受限来源指标依然是 HIT（权限不改变命中），而网段覆盖依然是 COVERED
        assertEquals("HIT", service.match(null, "restricted.internal", viewer).decision());
        assertEquals("COVERED", service.match(null, "10.200.1.1", viewer).decision());
    }
}
