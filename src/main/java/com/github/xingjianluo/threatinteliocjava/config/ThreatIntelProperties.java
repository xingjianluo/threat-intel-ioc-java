package com.github.xingjianluo.threatinteliocjava.config;

import com.github.xingjianluo.threatinteliocjava.refresh.RefreshPolicy;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 本地情报配置：情报目录、调用方目录、受限来源、刷新策略。全部来自本地文件/配置。
 */
@Component
@ConfigurationProperties(prefix = "threatintel")
public class ThreatIntelProperties {

    /** 情报文件目录（不存在时启动为空快照并告警）。 */
    private String feedDirectory = "data/feeds";

    /** 调用方目录 JSON 文件（缺失时使用内置演示目录）。 */
    private String callerFile = "data/callers.json";

    /** 抑制规则 JSONL 文件（缺失表示无抑制规则）。 */
    private String suppressionFile = "data/suppressions.jsonl";

    /** 受限来源名称列表。 */
    private List<String> restrictedSources = new ArrayList<>();

    /** 刷新策略。 */
    private RefreshPolicy refreshPolicy = RefreshPolicy.FAIL_CLOSED;

    /** 历史代际保留容量（默认最近 5 代；被淘汰的代际不可查询、不可回滚）。 */
    private int historyCapacity = 5;

    public String getFeedDirectory() {
        return feedDirectory;
    }

    public void setFeedDirectory(String feedDirectory) {
        this.feedDirectory = feedDirectory;
    }

    public String getCallerFile() {
        return callerFile;
    }

    public void setCallerFile(String callerFile) {
        this.callerFile = callerFile;
    }

    public String getSuppressionFile() {
        return suppressionFile;
    }

    public void setSuppressionFile(String suppressionFile) {
        this.suppressionFile = suppressionFile;
    }

    public List<String> getRestrictedSources() {
        return restrictedSources;
    }

    public void setRestrictedSources(List<String> restrictedSources) {
        this.restrictedSources = restrictedSources;
    }

    public RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public void setRefreshPolicy(RefreshPolicy refreshPolicy) {
        this.refreshPolicy = refreshPolicy;
    }

    public int getHistoryCapacity() {
        return historyCapacity;
    }

    public void setHistoryCapacity(int historyCapacity) {
        this.historyCapacity = historyCapacity;
    }
}
