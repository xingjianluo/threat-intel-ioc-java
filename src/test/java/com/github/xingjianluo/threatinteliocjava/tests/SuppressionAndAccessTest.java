package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.AccessDeniedException;
import com.github.xingjianluo.threatinteliocjava.access.Caller;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.access.Role;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.Indicator;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 抑制/白名单优先级与访问控制边界测试：
 * 1) 命中且被抑制 -> SUPPRESSED，reasons 含规则 id 与原因；未抑制命中 -> HIT；
 * 2) 域名抑制覆盖子域，网段抑制覆盖网内 IP；
 * 3) 无权限调用方查询受限来源明细 -> AccessDeniedException；
 * 4) 权限不足只影响明细可见性，绝不改变匹配判定本身；
 * 5) 匿名（无 apiKey）仍可得到一致的命中判定。
 */
class SuppressionAndAccessTest {

    private static final String FEEDS = "src/test/resources/data/feeds";
    private static final String SUP = "src/test/resources/data/suppressions.jsonl";
    private static final String CALLERS = "src/test/resources/data/callers.json";

    private ThreatIntelService service;
    private AccessControlService access;
    private CallerDirectory directory;

    @BeforeEach
    void setUp() {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        directory = new CallerDirectory(repo);
        directory.load(CALLERS);
        access = new AccessControlService(directory);
        MatchEngine engine = new MatchEngine(normalizer);
        service = new ThreatIntelService(repo, normalizer, engine, access);
        RefreshOutcome outcome = service.refresh(FEEDS, SUP,
                Set.of("vendorB"), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());
    }

    @Test
    void plainHitIsExplained() {
        Verdict v = service.match(null, "EVIL.example.com", null);
        assertEquals("HIT", v.decision());
        assertTrue(v.matched());
        assertFalse(v.suppressed());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("hit key=")));
    }

    @Test
    void suppressedDomainTakesPrecedenceOverHitAndIsExplained() {
        // safe.example.com 既是情报指标（HIGH），又在白名单 SUP-1001 中
        Verdict v = service.match("domain", "SAFE.Example.COM", null);
        assertTrue(v.matched(), "the indicator must still match");
        assertTrue(v.suppressed(), "suppression must take precedence");
        assertEquals("SUPPRESSED", v.decision());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("SUP-1001")),
                "reasons must cite rule id: " + v.reasons());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("known false positive")),
                "reasons must cite suppression reason: " + v.reasons());
    }

    @Test
    void cidrSuppressionCoversContainedIp() {
        // 10.1.2.3 命中 10.x 情报指标，同时被 SUP-1002 的 10.0.0.0/8 白名单覆盖
        Verdict v = service.match("ip", "012.1.2.3", null);
        assertTrue(v.matched());
        assertEquals("SUPPRESSED", v.decision());
        assertTrue(v.reasons().stream().anyMatch(r -> r.contains("SUP-1002")));
    }

    @Test
    void subdomainIsCoveredBySuppressionRule() {
        // 引擎规则：抑制域覆盖其子域
        Verdict v = service.match("domain", "host.safe.example.com", null);
        assertEquals("SUPPRESSED", v.decision());
    }

    @Test
    void cleanVerdictForUnknownValue() {
        Verdict v = service.match(null, "unknown.nobody.example", null);
        assertEquals("CLEAN", v.decision());
        assertFalse(v.matched());
    }

    @Test
    void restrictedDetailIsDeniedForViewerButAllowedForAnalyst() {
        // vendorB 是受限来源，restricted.internal 来自该来源
        String key = "DOMAIN:restricted.internal";
        Caller viewer = directory.resolve("viewer-key");
        Caller analyst = directory.resolve("analyst-key");
        Caller admin = directory.resolve("admin-key");
        assertEquals(Role.RESTRICTED_VIEWER, viewer.role());

        AccessDeniedException denied = assertThrows(AccessDeniedException.class,
                () -> service.lookupIndicatorsByKey(key, viewer));
        assertEquals("vendorB", denied.source());

        // 匿名同样拒绝
        assertThrows(AccessDeniedException.class,
                () -> service.lookupIndicatorsByKey(key, null));

        List<Indicator> analystView = service.lookupIndicatorsByKey(key, analyst);
        List<Indicator> adminView = service.lookupIndicatorsByKey(key, admin);
        assertEquals(1, analystView.size());
        assertEquals("restricted.internal", analystView.get(0).value());
        assertEquals(analystView, adminView);
    }

    @Test
    void denialDoesNotChangeTheHitVerdictAcrossCallers() {
        // 同一输入，三种调用方的命中结论必须完全一致
        Caller viewer = directory.resolve("viewer-key");
        Caller analyst = directory.resolve("analyst-key");
        Verdict anonymous = service.match(null, "restricted.internal", null);
        Verdict asViewer = service.match(null, "restricted.internal", viewer);
        Verdict asAnalyst = service.match(null, "restricted.internal", analyst);
        for (Verdict v : List.of(anonymous, asViewer, asAnalyst)) {
            assertEquals("HIT", v.decision());
            assertTrue(v.matched());
            assertEquals(anonymous.matchedKeys(), v.matchedKeys());
        }
        // 差异只体现在可见明细上：匿名/受限用户看到脱敏 key，分析师看到真实 key
        List<String> anonVisible = service.visibleKeys(anonymous.matchedKeys(), null);
        List<String> viewerVisible = service.visibleKeys(asViewer.matchedKeys(), viewer);
        List<String> analystVisible = service.visibleKeys(asAnalyst.matchedKeys(), analyst);
        assertTrue(anonVisible.get(0).contains("REDACTED"));
        assertTrue(viewerVisible.get(0).contains("REDACTED"));
        assertNotNull(analystVisible.get(0));
        assertFalse(analystVisible.get(0).contains("REDACTED"));
    }

    @Test
    void unknownApiKeyResolvesToAnonymous() {
        assertEquals(null, access.authenticate("no-such-key"));
        // 公开来源明细匿名也可见
        List<Indicator> publicHit = service.lookupIndicatorsByKey(
                "DOMAIN:evil.example.com", null);
        assertEquals(1, publicHit.size());
    }
}
