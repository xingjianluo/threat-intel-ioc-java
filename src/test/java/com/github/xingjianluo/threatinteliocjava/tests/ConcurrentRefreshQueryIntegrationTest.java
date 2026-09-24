package com.github.xingjianluo.threatinteliocjava.tests;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 并发刷新与并发匹配查询同时进行：
 * 任一查询只能得到完整快照上的自洽判定（HIT 必带命中信息），
 * 并发刷新不产生重复计数；受限明细权限边界在 HTTP 层稳定。
 */
@SpringBootTest
@AutoConfigureMockMvc
class ConcurrentRefreshQueryIntegrationTest {

    static Path fixtures() {
        URL url = ConcurrentRefreshQueryIntegrationTest.class.getClassLoader()
                .getResource("intel-fixtures");
        String p = url.getPath() != null && !url.getPath().isEmpty() ? url.getPath() : url.getFile();
        return Paths.get(p);
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("intel.directory", () -> fixtures().toString());
        registry.add("intel.refresh-on-startup", () -> "false");
        registry.add("intel.restricted-sources[0]", () -> "secret-feed.csv");
        registry.add("intel.source-roles.secret-feed.csv", () -> "secret:reader");
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private com.github.xingjianluo.threatinteliocjava.service.RefreshService refreshService;

    @Test
    @DisplayName("并发刷新+查询：结论集合稳定（仅 HIT/SUPPRESSED/NO_HIT/INVALID_INPUT 自洽）")
    void concurrentRefreshAndQuery() throws Exception {
        // 初始加载
        mvc.perform(post("/api/admin/refresh")).andExpect(status().isOk());

        String[] queries = {
                "1.2.3.4", "0x01020304", "10.10.5.5", "10.10.9.9",
                "malware.example.com", "sub.malware.example.com",
                "http://x.example.com/a?y=2&x=1", "unknown.example.org",
                "999.1.1.1", "safe.example.com"
        };
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> statuses = ConcurrentHashMap.newKeySet();
        AtomicInteger selfCheckFailures = new AtomicInteger();
        AtomicInteger httpFailures = new AtomicInteger();

        // 4 个线程反复刷新，8 个线程反复查询
        for (int t = 0; t < threads; t++) {
            boolean refresher = t < 4;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 25; i++) {
                        if (refresher) {
                            mvc.perform(post("/api/admin/refresh")).andExpect(status().isOk());
                        } else {
                            String q = queries[i % queries.length];
                            MvcResult mr = mvc.perform(get("/api/match").param("value", q))
                                    .andExpect(status().isOk())
                                    .andReturn();
                            String body = mr.getResponse().getContentAsString();
                            String st = extractStatus(body);
                            statuses.add(st);
                            // 自洽性：HIT 必带 match，SUPPRESSED 必带 suppressedBy
                            if ("HIT".equals(st) && !body.contains("\"match\":{")) {
                                selfCheckFailures.incrementAndGet();
                            }
                            if ("SUPPRESSED".equals(st) && !body.contains("\"suppressedBy\":{")) {
                                selfCheckFailures.incrementAndGet();
                            }
                        }
                    }
                } catch (Exception e) {
                    httpFailures.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

        assertEquals(0, httpFailures.get(), "不应有 HTTP 失败");
        assertEquals(0, selfCheckFailures.get(), "不应出现部分加载导致的自相矛盾判定");
        // 并发期间观测到的结论集合稳定
        Set<String> allowed = new HashSet<>(Set.of("HIT", "SUPPRESSED", "NO_HIT", "INVALID_INPUT"));
        assertTrue(allowed.containsAll(statuses), "出现未知结论: " + statuses);
        assertTrue(statuses.contains("HIT"));
        assertTrue(statuses.contains("SUPPRESSED"));

        // 刷新计数稳定：最终再来一次必为 UNCHANGED，指标数恒定
        String finalBody = mvc.perform(post("/api/admin/refresh")).andReturn().getResponse()
                .getContentAsString();
        assertTrue(finalBody.contains("\"status\":\"UNCHANGED\""), finalBody);
        var report = refreshService.lastReport();
        assertTrue(report.totalIndicators() >= 5);
    }

    @Test
    @DisplayName("受限明细：匿名 403、错误角色 403、正确角色 200；公开明细 200")
    void httpAccessControl() throws Exception {
        mvc.perform(post("/api/admin/refresh")).andExpect(status().isOk());

        mvc.perform(get("/api/indicators/domain/top.secret.example"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/indicators/domain/top.secret.example").header("X-Roles", "admin"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/indicators/domain/top.secret.example")
                        .header("X-Roles", "secret:reader"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/indicators/ip/1.2.3.4")).andExpect(status().isOk());
        mvc.perform(get("/api/indicators/ip/9.9.9.9")).andExpect(status().isNotFound());
    }

    private static String extractStatus(String json) {
        int i = json.indexOf("\"status\":\"");
        return json.substring(i + 10, json.indexOf('"', i + 10));
    }
}
