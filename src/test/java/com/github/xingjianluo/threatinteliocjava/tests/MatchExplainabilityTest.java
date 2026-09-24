package com.github.xingjianluo.threatinteliocjava.tests;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.xingjianluo.threatinteliocjava.access.AccessControlService;
import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.match.MatchEngine;
import com.github.xingjianluo.threatinteliocjava.model.Verdict;
import com.github.xingjianluo.threatinteliocjava.normalize.Normalizer;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import com.github.xingjianluo.threatinteliocjava.source.LocalFeedRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 可解释性测试：每次判定必须在日志中留下原始输入、归一值、结论与命中/抑制依据；
 * 拒绝刷新也必须带可区分的 RejectionCode。
 */
class MatchExplainabilityTest {

    private ListAppender<ILoggingEvent> appender;
    private Logger engineLogger;
    private Logger serviceLogger;

    @BeforeEach
    void attach() {
        appender = new ListAppender<>();
        appender.start();
        engineLogger = (Logger) LoggerFactory.getLogger(MatchEngine.class);
        serviceLogger = (Logger) LoggerFactory.getLogger(ThreatIntelService.class);
        engineLogger.addAppender(appender);
        serviceLogger.addAppender(appender);
        engineLogger.setLevel(Level.INFO);
        serviceLogger.setLevel(Level.INFO);
    }

    @AfterEach
    void detach() {
        engineLogger.detachAppender(appender);
        serviceLogger.detachAppender(appender);
    }

    @Test
    void matchLogContainsInputNormalizationDecisionAndBasis() {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        CallerDirectory dir = new CallerDirectory(repo);
        dir.loadBuiltinFallback();
        ThreatIntelService service = new ThreatIntelService(repo, normalizer,
                new MatchEngine(normalizer), new AccessControlService(dir));
        service.refresh("src/test/resources/data/feeds",
                "src/test/resources/data/suppressions.jsonl",
                Set.of(), RefreshPolicy.FAIL_CLOSED);

        Verdict v = service.match(null, "SAFE.Example.COM", null);
        org.junit.jupiter.api.Assertions.assertEquals("SUPPRESSED", v.decision());

        List<String> messages = appender.list.stream().map(Object::toString).toList();
        String joined = String.join("\n", messages);
        assertTrue(joined.contains("input='SAFE.Example.COM'"), "log must contain raw input");
        assertTrue(joined.contains("normalized='safe.example.com'"),
                "log must contain normalized value");
        assertTrue(joined.contains("decision=SUPPRESSED"), "log must contain decision");
        assertTrue(joined.contains("SUP-1001"), "log must cite suppression rule id");
        assertTrue(joined.contains("hit key=DOMAIN:safe.example.com"),
                "log must cite matched key");
    }

    @Test
    void rejectedRefreshLogsDistinguishableCodes() {
        Normalizer normalizer = new Normalizer();
        LocalFeedRepository repo = new LocalFeedRepository(
                List.of(new JsonlFeedParser(), new CsvFeedParser()));
        CallerDirectory dir = new CallerDirectory(repo);
        dir.loadBuiltinFallback();
        ThreatIntelService service = new ThreatIntelService(repo, normalizer,
                new MatchEngine(normalizer), new AccessControlService(dir));
        service.refresh("src/test/resources/data/malformed-feeds", "missing.jsonl",
                Set.of(), RefreshPolicy.FAIL_CLOSED);

        String joined = appender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .reduce("", (a, b) -> a + "\n" + b);
        assertTrue(joined.contains("INVALID_VALUE"), "must log INVALID_VALUE: " + joined);
        assertTrue(joined.contains("UNSUPPORTED_TYPE"), "must log UNSUPPORTED_TYPE: " + joined);
        assertTrue(joined.contains("REJECTED_NO_PREVIOUS_STATE")
                || joined.contains("batch discarded"), "must log rejection conclusion");
    }
}
