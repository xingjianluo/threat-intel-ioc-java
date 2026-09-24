package com.github.xingjianluo.threatinteliocjava.config;

import com.github.xingjianluo.threatinteliocjava.model.RefreshReport;
import com.github.xingjianluo.threatinteliocjava.service.RefreshService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;

/**
 * 启用配置属性绑定，并在启动完成后做一次初始刷新。
 * 初始刷新失败不阻止应用启动（健康接口可见未加载状态，旧快照为空即查询返回 NO_HIT 说明）。
 */
@Configuration
@ConfigurationPropertiesScan
public class IntelConfig {

    private static final Logger log = LoggerFactory.getLogger(IntelConfig.class);

    private final RefreshService refreshService;
    private final IntelProperties properties;

    public IntelConfig(RefreshService refreshService, IntelProperties properties) {
        this.refreshService = refreshService;
        this.properties = properties;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void refreshOnStartup() {
        if (!properties.refreshOnStartup()) {
            log.info("启动刷新已关闭(intel.refresh-on-startup=false)");
            return;
        }
        RefreshReport report = refreshService.refresh();
        log.info("启动刷新结论: status={} success={} 指标数={} 拒绝={} 失败原因={}",
                report.status(), report.success(), report.totalIndicators(),
                report.rejections().size(), report.failureReason());
    }
}
