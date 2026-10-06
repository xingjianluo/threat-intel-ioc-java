package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.SourceHealth;
import com.github.xingjianluo.threatinteliocjava.model.SourceStatus;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 来源健康与刷新代际留痕测试：
 * 1) 每代刷新可追溯：哪些来源被采用、哪些被跳过、跳过是合法为空还是读取失败；
 * 2) 来源暂时不可读时刷新明确失败（两种策略下都不生效），匹配继续按上一代判定；
 * 3) 读取异常绝不被当成合法空情报（SKIPPED_UNREADABLE != SKIPPED_EMPTY）。
 */
class SourceHealthRefreshTest {

    @TempDir
    Path tempDir;

    private ThreatIntelService service;

    @BeforeEach
    void setUp() {
        service = newService();
    }

    private ThreatIntelService newService() {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        CallerDirectory directory = new CallerDirectory(repo);
        directory.loadBuiltinFallback();
        return new ThreatIntelService(repo, normalizer,
                new MatchEngine(normalizer), new AccessControlService(directory));
    }

    /** 造一个目录：alpha 来源正常（1 条指标），beta 来源合法为空。 */
    private Path dirWithEmptySource() throws IOException {
        return dirWithEmptySource("v1");
    }

    private Path dirWithEmptySource(String name) throws IOException {
        Path dir = Files.createDirectory(tempDir.resolve(name));
        Files.writeString(dir.resolve("alpha.jsonl"),
                "{\"type\":\"domain\",\"value\":\"alpha-evil.example\",\"severity\":\"high\"}\n");
        Files.writeString(dir.resolve("beta.jsonl"), "");
        return dir;
    }

    /** 造一个目录：alpha 来源正常，beta 来源这次读不出来（CSV 缺表头 -> 文件级失败）。 */
    private Path dirWithUnreadableSource() throws IOException {
        Path dir = Files.createDirectory(tempDir.resolve("v2"));
        Files.writeString(dir.resolve("alpha.jsonl"),
                "{\"type\":\"domain\",\"value\":\"alpha-evil.example\",\"severity\":\"high\"}\n");
        Files.writeString(dir.resolve("beta.csv"), "this is not a csv header at all\n1,2,3\n");
        return dir;
    }

    private static Map<String, SourceHealth> bySource(List<SourceHealth> health) {
        return health.stream().collect(Collectors.toMap(SourceHealth::source, Function.identity()));
    }

    @Test
    void eachGenerationRecordsPerSourceHealthTraceably() throws Exception {
        RefreshOutcome outcome = service.refresh(dirWithEmptySource().toString(),
                "missing-suppressions.jsonl", Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", outcome.outcome());

        // 刷新结论与生效快照都带来源健康留痕
        Map<String, SourceHealth> fromOutcome = bySource(outcome.sourceHealth());
        Map<String, SourceHealth> fromSnapshot = bySource(service.currentSnapshot().sourceHealth());
        for (Map<String, SourceHealth> health : List.of(fromOutcome, fromSnapshot)) {
            assertEquals(SourceStatus.ADOPTED, health.get("alpha").status());
            assertEquals(SourceStatus.SKIPPED_EMPTY, health.get("beta").status());
            assertTrue(health.get("beta").detail().contains("legitimately empty"),
                    "empty source must be explained as legitimate: " + health.get("beta"));
        }
    }

    @Test
    void unreadableSourceFailsRefreshAndIsNotTreatedAsEmptyIntel() throws Exception {
        // 先建立一份完整可用的 v1
        RefreshOutcome good = service.refresh(dirWithEmptySource().toString(),
                "missing-suppressions.jsonl", Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals("APPLIED", good.outcome());

        // beta 这次读不出来：即使 ACCEPT_PARTIAL 也整批不生效
        RefreshOutcome failed = service.refresh(dirWithUnreadableSource().toString(),
                "missing-suppressions.jsonl", Set.of(), RefreshPolicy.ACCEPT_PARTIAL);
        assertEquals("REJECTED_PRESERVED", failed.outcome(),
                "an unreadable source must fail the refresh under any policy");
        assertFalse(failed.failures().isEmpty(), "failure must be explicitly reported");

        // 读取异常与合法空情报可区分
        Map<String, SourceHealth> health = bySource(failed.sourceHealth());
        assertEquals(SourceStatus.SKIPPED_UNREADABLE, health.get("beta").status());
        assertEquals(SourceStatus.ADOPTED, health.get("alpha").status());

        // 匹配继续按上一代完整可用的结果判定
        assertEquals(1, service.currentSnapshot().version());
        Verdict v = service.match("domain", "alpha-evil.example", null);
        assertEquals("HIT", v.decision());
        // 当前生效代的健康留痕仍是上一代成功刷新的记录（beta 合法为空）
        Map<String, SourceHealth> active = bySource(service.currentSnapshot().sourceHealth());
        assertEquals(SourceStatus.SKIPPED_EMPTY, active.get("beta").status());
    }

    @Test
    void firstLoadWithUnreadableSourceHasNoPreviousState() throws Exception {
        RefreshOutcome failed = service.refresh(dirWithUnreadableSource().toString(),
                "missing-suppressions.jsonl", Set.of(), RefreshPolicy.FAIL_CLOSED);
        assertEquals("REJECTED_NO_PREVIOUS_STATE", failed.outcome());
        assertEquals(0, service.currentSnapshot().version());
        assertTrue(service.currentSnapshot().indicators().isEmpty());
        assertEquals(SourceStatus.SKIPPED_UNREADABLE,
                bySource(failed.sourceHealth()).get("beta").status());
        // 空快照上的查询是合法 CLEAN，但刷新结论明确是失败而不是"空情报"
        assertEquals("CLEAN", service.match("domain", "alpha-evil.example", null).decision());
    }

    @Test
    void legitimatelyEmptySourceDoesNotFailRefresh() throws Exception {
        // 合法空来源在两种策略下都不构成失败（每个策略用独立 service，避免内容哈希去重）
        int n = 0;
        for (RefreshPolicy policy : List.of(RefreshPolicy.FAIL_CLOSED, RefreshPolicy.ACCEPT_PARTIAL)) {
            ThreatIntelService fresh = newService();
            Path dir = dirWithEmptySource("empty-ok-" + (n++));
            RefreshOutcome outcome = fresh.refresh(dir.toString(),
                    "missing-suppressions.jsonl", Set.of(), policy);
            assertEquals("APPLIED", outcome.outcome(), "policy=" + policy);
            assertEquals(SourceStatus.SKIPPED_EMPTY,
                    bySource(outcome.sourceHealth()).get("beta").status());
            // 相同内容重复刷新 -> APPLIED_UNCHANGED，生效代的健康留痕保持不变
            RefreshOutcome again = fresh.refresh(dir.toString(),
                    "missing-suppressions.jsonl", Set.of(), policy);
            assertEquals("APPLIED_UNCHANGED", again.outcome());
            assertEquals(SourceStatus.SKIPPED_EMPTY,
                    bySource(fresh.currentSnapshot().sourceHealth()).get("beta").status());
        }
    }
}
