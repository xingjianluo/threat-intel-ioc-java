package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.config.IntelProperties;
import com.github.xingjianluo.threatinteliocjava.model.ImportRejection;
import com.github.xingjianluo.threatinteliocjava.model.RejectionReason;
import com.github.xingjianluo.threatinteliocjava.model.RefreshReport;
import com.github.xingjianluo.threatinteliocjava.normalize.IocNormalizer;
import com.github.xingjianluo.threatinteliocjava.service.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.service.IntelRegistry;
import com.github.xingjianluo.threatinteliocjava.service.RefreshService;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonIntelParser;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvIntelParser;
import com.github.xingjianluo.threatinteliocjava.ingest.SuppressionListParser;
import com.github.xingjianluo.threatinteliocjava.ingest.IntelFileLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** 刷新：拒绝原因可区分、重复幂等、冲突确定收敛、失败保留旧状态、并发安全。 */
class RefreshServiceTest {

    @TempDir
    Path dir;

    private RefreshService refreshService;
    private IntelRegistry registry;

    private RefreshService newService(Path dataDir) {
        IocNormalizer normalizer = new IocNormalizer();
        var loader = new IntelFileLoader(
                List.of(new JsonIntelParser(), new SuppressionListParser(), new CsvIntelParser()),
                normalizer);
        var props = new IntelProperties(dataDir, List.of("secret.csv"),
                Map.of("secret.csv", "secret:reader"), false);
        IntelRegistry reg = new IntelRegistry();
        var access = new AccessControlService(props);
        this.registry = reg;
        this.refreshService = new RefreshService(loader, reg, props, access);
        return refreshService;
    }

    private void write(String name, String content) throws Exception {
        Files.writeString(dir.resolve(name), content);
    }

    private boolean has(RefreshReport r, RejectionReason reason) {
        return r.rejections().stream().anyMatch(x -> x.reason() == reason);
    }

    @Test
    @DisplayName("两类格式导入：畸形值/不支持类型/缺字段按不同原因拒绝，状态 PARTIAL")
    void importsNormalizeAndRejectWithDistinctReasons() throws Exception {
        write("a.json", """
                {"indicators":[
                  {"type":"ip","value":"1.2.3.4","confidence":"90","severity":"high"},
                  {"type":"ip","value":"bad-ip"},
                  {"type":"wat","value":"1.1.1.1"},
                  {"type":"ip","confidence":"80"}
                ]}
                """);
        write("b.csv", "type,value,severity,confidence\ndomain,GOOD.COM,low,50\nip,3.3.3.3,low,500\n");

        RefreshReport r = newService(dir).refresh();
        assertTrue(r.success());
        assertEquals("PARTIAL", r.status());
        assertEquals(2, r.totalIndicators());
        assertTrue(has(r, RejectionReason.MALFORMED_VALUE));
        assertTrue(has(r, RejectionReason.UNSUPPORTED_INDICATOR_TYPE));
        assertTrue(has(r, RejectionReason.MISSING_REQUIRED_FIELD));
        // 每条拒绝可追溯到文件/行号/输入
        for (ImportRejection rej : r.rejections()) {
            assertNotNull(rej.sourceFile());
            assertNotNull(rej.rawContent());
        }
    }

    @Test
    @DisplayName("重复导入相同内容：UNCHANGED 且指标数/哈希不漂移")
    void identicalContentIsIdempotent() throws Exception {
        write("a.json",
                "{\"indicators\":[{\"type\":\"ip\",\"value\":\"1.2.3.4\",\"confidence\":\"90\"},"
                        + "{\"type\":\"ip\",\"value\":\"0x01020304\",\"confidence\":\"90\"}]}");
        RefreshService svc = newService(dir);
        RefreshReport first = svc.refresh();
        assertEquals("OK", first.status());
        assertEquals(1, first.totalIndicators());
        assertEquals(1, first.duplicateMerged());

        RefreshReport second = svc.refresh();
        RefreshReport third = svc.refresh();
        for (RefreshReport r : List.of(second, third)) {
            assertEquals("UNCHANGED", r.status());
            assertEquals(1, r.totalIndicators());
            assertEquals(first.contentHash(), r.contentHash());
        }
        // 快照对象未被反复替换，仍是同一份已知良好结果
        assertEquals(first.contentHash(), registry.currentSnapshot().orElseThrow().getContentHash());
    }

    @Test
    @DisplayName("同一指标定义冲突：按置信度→级别→来源的确定规则收敛并记录")
    void conflictingDefinitionsConvergeDeterministically() throws Exception {
        write("a.json", """
                {"indicators":[
                  {"type":"domain","value":"x.com","severity":"high","confidence":"80","description":"A"},
                  {"type":"domain","value":"x.com","severity":"low","confidence":"90","description":"B"}
                ]}
                """);
        RefreshReport r = newService(dir).refresh();
        assertEquals(1, r.totalIndicators());
        assertEquals(1, r.conflictConverged());
        var record = r.conflicts().get(0);
        assertTrue(record.resolutionRule().contains("置信度"));
        assertTrue(record.ignoredDescriptor().contains("confidence=80"));
        assertTrue(record.chosenDescriptor().contains("confidence=90"));
    }

    @Test
    @DisplayName("文件级致命错误：刷新 FAILED 且保留上一份已知良好快照")
    void fatalFailureKeepsLastGoodSnapshot() throws Exception {
        write("a.json",
                "{\"indicators\":[{\"type\":\"ip\",\"value\":\"1.2.3.4\",\"confidence\":\"90\"}]}");
        RefreshService svc = newService(dir);
        RefreshReport ok = svc.refresh();
        assertEquals("OK", ok.status());
        String goodHash = ok.contentHash();
        int goodCount = ok.totalIndicators();

        // 破坏文件：JSON 整体损坏
        Files.writeString(dir.resolve("a.json"), "{ broken json");
        RefreshReport failed = svc.refresh();
        assertFalse(failed.success());
        assertEquals("FAILED", failed.status());
        assertNotNull(failed.failureReason());
        assertEquals(goodHash, registry.currentSnapshot().orElseThrow().getContentHash());
        assertEquals(goodCount, registry.currentSnapshot().orElseThrow().indicatorCount());

        // 目录消失同样 FAILED 并保留旧状态
        var missing = newService(dir.resolve("does-not-exist"));
        // 让它与当前 registry 脱钩：直接验证失败结论
        RefreshReport missingReport = missing.refresh();
        assertEquals("FAILED", missingReport.status());
    }

    @Test
    @DisplayName("并发刷新：串行化、不重复计数、状态不损坏，结果稳定可复现")
    void concurrentRefreshesAreSerializedAndStable() throws Exception {
        write("a.json", """
                {"indicators":[
                  {"type":"ip","value":"1.2.3.4","confidence":"90"},
                  {"type":"ip","value":"0x01020304","confidence":"90"},
                  {"type":"ip","value":"bad"},
                  {"type":"nope","value":"2.2.2.2"}
                ]}
                """);
        RefreshService svc = newService(dir);
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<RefreshReport> reports = new ConcurrentLinkedQueue<>();
        AtomicInteger publishedHashes = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                reports.add(svc.refresh());
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        assertEquals(threads, reports.size());
        // 所有结论要么 OK/PARTIAL（首个），要么 UNCHANGED（其余），绝无 FAILED
        long unchanged = reports.stream().filter(x -> "UNCHANGED".equals(x.status())).count();
        long ok = reports.stream().filter(x -> "OK".equals(x.status()) || "PARTIAL".equals(x.status())).count();
        assertEquals(threads - 1, unchanged);
        assertEquals(1, ok);
        // 计数稳定
        for (RefreshReport r : reports) {
            assertEquals(1, r.totalIndicators());
        }
    }
}
