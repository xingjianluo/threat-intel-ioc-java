package com.github.xingjianluo.threatinteliocjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.util.List;

/**
 * 本地情报配置（intel.* 前缀）：
 * intel.directory 情报目录；intel.restricted-sources 受限来源名；
 * intel.source-roles.[feed]=role1,role2 来源到所需角色的映射。
 */
@ConfigurationProperties(prefix = "intel")
public record IntelProperties(
        Path directory,
        List<String> restrictedSources,
        java.util.Map<String, String> sourceRoles,
        boolean refreshOnStartup
) {
    public IntelProperties {
        if (directory == null) {
            directory = Path.of("intel-data");
        }
        if (restrictedSources == null) {
            restrictedSources = List.of();
        }
        if (sourceRoles == null) {
            sourceRoles = java.util.Map.of();
        }
    }
}
