package com.github.xingjianluo.threatinteliocjava.model;

/** 统一指标类型。 */
public enum IndicatorType {
    IP,
    CIDR,
    DOMAIN,
    URL,
    HASH;

    /** 把外部格式中的类型代码（大小写不敏感）解析为枚举，无法识别时返回 null。 */
    public static IndicatorType fromCode(String code) {
        if (code == null) {
            return null;
        }
        return switch (code.trim().toLowerCase().replace('-', '_')) {
            case "ip", "ipv4", "ipv6", "address" -> IP;
            case "cidr", "net", "network", "subnet" -> CIDR;
            case "domain", "hostname", "host" -> DOMAIN;
            case "url", "uri" -> URL;
            case "hash", "md5", "sha1", "sha256" -> HASH;
            default -> null;
        };
    }
}
