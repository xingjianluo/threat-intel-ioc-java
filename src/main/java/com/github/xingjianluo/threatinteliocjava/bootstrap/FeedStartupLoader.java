package com.github.xingjianluo.threatinteliocjava.bootstrap;

import com.github.xingjianluo.threatinteliocjava.access.CallerDirectory;
import com.github.xingjianluo.threatinteliocjava.config.ThreatIntelProperties;
import com.github.xingjianluo.threatinteliocjava.refresh.RefreshOutcome;
import com.github.xingjianluo.threatinteliocjava.refresh.ThreatIntelService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * 启动时加载调用方目录并执行首次情报刷新。
 *
 * <p>情报目录不存在不阻断启动（进入空快照状态，刷新结论为 REJECTED_NO_PREVIOUS_STATE
 * 仅当文件存在但含坏条目时出现）。坏条目在 FAIL_CLOSED 下使首装不生效并打印可区分原因。
 */
@Component
public class FeedStartupLoader {

    private static final Logger log = LoggerFactory.getLogger(FeedStartupLoader.class);

    private final ThreatIntelService service;
    private final ThreatIntelProperties properties;
    private final CallerDirectory callerDirectory;

    public FeedStartupLoader(ThreatIntelService service,
                             ThreatIntelProperties properties,
                             CallerDirectory callerDirectory) {
        this.service = service;
        this.properties = properties;
        this.callerDirectory = callerDirectory;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void loadOnStartup() {
        callerDirectory.load(properties.getCallerFile());
        RefreshOutcome outcome = service.refresh(
                properties.getFeedDirectory(),
                properties.getSuppressionFile(),
                Set.copyOf(properties.getRestrictedSources()),
                properties.getRefreshPolicy());
        log.info("startup refresh outcome: {} version={} message='{}' failures={}",
                outcome.outcome(), outcome.version(), outcome.message(),
                outcome.failures().size());
        outcome.failures().forEach(f -> log.warn("rejected on startup: source={} item={} code={} detail={}",
                f.source(), f.rawLine(), f.code(), f.detail()));
    }
}
