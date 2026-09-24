package com.github.xingjianluo.threatinteliocjava.tests;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 刷新整体失败：接口给出 FAILED 结论，且匹配继续基于上一份已知良好快照。
 * 通过运行时覆盖 intel.directory 到独立临时目录，避免污染其他测试。
 */
@SpringBootTest
@AutoConfigureMockMvc
class RefreshFailureRetentionIntegrationTest {

    @TempDir
    static Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("intel.directory", () -> tempDir.toString());
        registry.add("intel.refresh-on-startup", () -> "false");
        registry.add("intel.restricted-sources[0]", () -> "secret-feed.csv");
    }

    @Autowired
    private MockMvc mvc;

    private static void write(String name, String body) throws IOException {
        Files.writeString(tempDir.resolve(name), body);
    }

    @Test
    @DisplayName("文件损坏后刷新 FAILED，旧快照继续提供命中")
    void failedRefreshKeepsLastGood() throws Exception {
        write("good.json", """
                {"indicators":[
                  {"type":"ip","value":"5.6.7.8","severity":"high","confidence":"90"}
                ]}
                """);

        String okBody = mvc.perform(post("/api/admin/refresh"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(okBody.contains("\"status\":\"OK\""), okBody);

        // 旧快照可用
        mvc.perform(get("/api/match").param("value", "5.6.7.8"))
                .andExpect(status().isOk())
                .andDo(r -> assertTrue(r.getResponse().getContentAsString().contains("\"status\":\"HIT\"")));

        // 破坏：JSON 整体损坏（文件级致命错误）
        write("good.json", "{ this is not valid json ");
        String failedBody = mvc.perform(post("/api/admin/refresh"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(failedBody.contains("\"success\":false"), failedBody);
        assertTrue(failedBody.contains("\"status\":\"FAILED\""), failedBody);
        assertTrue(failedBody.contains("文件级解析错误"), failedBody);

        // 旧快照仍然可用：判定不变
        mvc.perform(get("/api/match").param("value", "5.6.7.8"))
                .andExpect(status().isOk())
                .andDo(r -> assertTrue(r.getResponse().getContentAsString().contains("\"status\":\"HIT\""),
                        "刷新失败后旧快照必须继续命中"));
    }
}
