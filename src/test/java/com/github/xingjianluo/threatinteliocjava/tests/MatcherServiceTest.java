package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.config.IntelProperties;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvIntelParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonIntelParser;
import com.github.xingjianluo.threatinteliocjava.ingest.IntelFileLoader;
import com.github.xingjianluo.threatinteliocjava.ingest.SuppressionListParser;
import com.github.xingjianluo.threatinteliocjava.model.MatchVerdict;
import com.github.xingjianluo.threatinteliocjava.normalize.IocNormalizer;
import com.github.xingjianluo.threatinteliocjava.service.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.service.AccessDeniedException;
import com.github.xingjianluo.threatinteliocjava.service.IndicatorNotFoundException;
import com.github.xingjianluo.threatinteliocjava.service.IntelRegistry;
import com.github.xingjianluo.threatinteliocjava.service.MatcherService;
import com.github.xingjianluo.threatinteliocjava.service.RefreshService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** 匹配与访问控制：等价命中、抑制优先、无快照、权限不影响判定。 */
class MatcherServiceTest {

    private static MatcherService matcher;
    private static RefreshService refreshService;

    @BeforeAll
    static void init() {
        URL url = MatcherServiceTest.class.getClassLoader().getResource("intel-fixtures");
        Path dir = Paths.get(url.getPath() != null && !url.getPath().isEmpty()
                ? url.getPath() : url.getFile());
        IocNormalizer normalizer = new IocNormalizer();
        var loader = new IntelFileLoader(List.of(new JsonIntelParser(),
                new SuppressionListParser(), new CsvIntelParser()), normalizer);
        var props = new IntelProperties(dir, List.of("secret-feed.csv"),
                Map.of("secret-feed.csv", "secret:reader"), false);
        IntelRegistry registry = new IntelRegistry();
        var access = new AccessControlService(props);
        refreshService = new RefreshService(loader, registry, props, access);
        matcher = new MatcherService(registry, normalizer, access);
        RefreshReportAsserts(refreshService.refresh());
    }

    private static void RefreshReportAsserts(
            com.github.xingjianluo.threatinteliocjava.model.RefreshReport r) {
        // 夹具含坏行，预期 PARTIAL
        assertTrue(r.success());
    }

    @Test
    @DisplayName("IP 混淆写法等价命中")
    void ipObfuscationHits() {
        MatchVerdict v = matcher.match("0x01020304", null, Set.of());
        assertEquals("HIT", v.status());
        assertEquals("1.2.3.4", v.normalizedValue());
    }

    @Test
    @DisplayName("网段包含：10.10.9.9 命中 /16")
    void cidrContainmentHits() {
        MatchVerdict v = matcher.match("10.10.9.9", null, Set.of());
        assertEquals("HIT", v.status());
        assertNotNull(v.match());
        assertTrue(v.reason().contains("网段"));
    }

    @Test
    @DisplayName("域名大小写与子域等价命中（取最具体指标）；命中仍可被更宽的白名单抑制")
    void domainCaseAndSubdomain() {
        MatchVerdict v = matcher.match("DEEP.SUB.MALWARE.EXAMPLE.COM", null, Set.of());
        // 命中最具体的子域指标 sub.malware.example.com，但 FP-DUP(malware.example.com)
        // 作为更宽的白名单规则优先抑制，结论仍保留具体命中依据
        assertNotNull(v.match());
        assertEquals("sub.malware.example.com", v.match().canonicalValue());
        assertEquals("SUPPRESSED", v.status());
        assertEquals("FP-DUP", v.suppressedBy().id());
    }

    @Test
    @DisplayName("URL 参数顺序/大小写等价命中")
    void urlEquivalenceHits() {
        MatchVerdict v = matcher.match("http://x.example.com/a?y=2&x=1", null, Set.of());
        assertEquals("HIT", v.status());
        assertEquals("http://x.example.com/a?x=1&y=2", v.normalizedValue());
    }

    @Test
    @DisplayName("抑制/白名单优先于命中：malware.example.com 命中但被 FP-DUP 抑制")
    void suppressionTakesPrecedence() {
        MatchVerdict v = matcher.match("malware.example.com", null, Set.of());
        assertEquals("SUPPRESSED", v.status());
        assertNotNull(v.match(), "仍需给出被抑制的命中依据");
        assertNotNull(v.suppressedBy());
        assertEquals("FP-DUP", v.suppressedBy().id());
        assertTrue(v.reason().contains("优先"));
    }

    @Test
    @DisplayName("网段抑制：10.10.5.5 命中 /16 但被更具体的 /24 白名单抑制")
    void cidrSuppression() {
        MatchVerdict v = matcher.match("10.10.5.5", null, Set.of());
        assertEquals("SUPPRESSED", v.status());
        assertEquals("FP-CIDR", v.suppressedBy().id());
        assertNotNull(v.match());
    }

    @Test
    @DisplayName("仅抑制无命中也是 SUPPRESSED；无匹配为 NO_HIT；非法输入 INVALID_INPUT")
    void statuses() {
        assertEquals("SUPPRESSED",
                matcher.match("safe.example.com", null, Set.of()).status());
        assertEquals("NO_HIT",
                matcher.match("unknown.example.org", null, Set.of()).status());
        assertEquals("INVALID_INPUT",
                matcher.match("999.1.1.1", "ip", Set.of()).status());
        assertEquals("INVALID_INPUT",
                matcher.match("???", null, Set.of()).status());
    }

    @Test
    @DisplayName("无权限不影响命中判定本身")
    void permissionDoesNotChangeVerdict() {
        MatchVerdict anonymous = matcher.match("top.secret.example", null, Set.of());
        MatchVerdict privileged = matcher.match("top.secret.example", null,
                Set.of("secret:reader"));
        assertEquals("HIT", anonymous.status());
        assertEquals("HIT", privileged.status());
        assertEquals(anonymous.normalizedValue(), privileged.normalizedValue());
        assertEquals(anonymous.match(), privileged.match());
    }

    @Test
    @DisplayName("明细查询：匿名/错误角色 403，正确角色允许，不存在 404")
    void detailAccessControl() {
        assertThrows(AccessDeniedException.class,
                () -> matcher.detail("domain", "top.secret.example", Set.of()));
        assertThrows(AccessDeniedException.class,
                () -> matcher.detail("domain", "top.secret.example", Set.of("admin")));
        var ok = matcher.detail("domain", "TOP.SECRET.EXAMPLE", Set.of("secret:reader"));
        assertEquals("top.secret.example", ok.canonicalValue());

        var publicInd = matcher.detail("ip", "1.2.3.4", Set.of());
        assertEquals("1.2.3.4", publicInd.canonicalValue());

        assertThrows(IndicatorNotFoundException.class,
                () -> matcher.detail("ip", "9.9.9.9", Set.of()));
        assertThrows(IllegalArgumentException.class,
                () -> matcher.detail("banana", "1.2.3.4", Set.of()));
    }

    @Test
    @DisplayName("未加载快照时判定为 NO_HIT 并说明原因")
    void emptyRegistry() {
        var emptyMatcher = new MatcherService(new IntelRegistry(), new IocNormalizer(),
                new AccessControlService(new IntelProperties(
                        Path.of("."), List.of(), Map.of(), false)));
        MatchVerdict v = emptyMatcher.match("1.2.3.4", null, Set.of());
        assertEquals("NO_HIT", v.status());
        assertTrue(v.reason().contains("尚未加载"));
    }
}
