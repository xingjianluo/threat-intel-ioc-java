package com.github.xingjianluo.threatinteliocjava.normalize;

import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import org.springframework.stereotype.Component;

import java.net.IDN;
import java.net.URI;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * 指标归一器：把原始写法收敛为唯一规范值。
 *
 * <p>等价规则（确定、可解释）：
 * <ul>
 *   <li>IP：大小写无关；支持常见混淆写法——32 位十进制整数（2130706433）与
 *       0x 十六进制整数（0x7F000001）等价于点分十进制；IPv6 统一压缩写法；
 *       不做任何 DNS 解析，主机名不会被当作 IP。</li>
 *   <li>网段：主机位清零后比较，如 192.168.1.50/24 与 192.168.1.0/24 等价。</li>
 *   <li>域名：小写；去末尾点；Unicode 域名经 IDN 转 ASCII（与 xn-- 写法等价）；
 *       全角点 U+FF0E / 中文句号 U+3002 视作点；域名与子域由匹配层处理。</li>
 *   <li>URL：scheme/host 小写；host 走 IP/域名归一；省略 http:80、https:443 默认端口；
 *       路径为空归一为 /；查询参数按名再按值排序；去 fragment；去 userinfo。</li>
 *   <li>哈希：转小写十六进制，长度必须为 32/40/64（md5/sha1/sha256）。</li>
 * </ul>
 */
@Component
public class IocNormalizer {

    private static final Pattern HEX_HASH = Pattern.compile("^[0-9a-fA-F]+$");

    public String normalize(IndicatorType type, String rawValue) {
        if (type == null) {
            throw new NormalizationException("指标类型为空");
        }
        if (rawValue == null || rawValue.isBlank()) {
            throw new NormalizationException("指标值为空");
        }
        return switch (type) {
            case IP -> ip(rawValue);
            case CIDR -> {
                Cidr c = cidr(rawValue);
                yield c.networkAddress() + "/" + c.prefixLength();
            }
            case DOMAIN -> domain(rawValue);
            case URL -> url(rawValue);
            case HASH -> hash(rawValue);
        };
    }

    /** 规范 IPv4/IPv6 地址（拒绝主机名）。 */
    public String ip(String raw) {
        String s = raw.trim();
        if (s.isEmpty()) {
            throw new NormalizationException("IP 为空");
        }
        if (s.indexOf(':') >= 0) {
            if (s.indexOf('%') >= 0) {
                throw new NormalizationException("不支持带 zone id 的 IPv6: " + raw);
            }
            byte[] b = Cidr.parseIp6(s);
            return Cidr.formatIp6(b);
        }
        if (s.indexOf('.') >= 0) {
            byte[] b = Cidr.parseIp4(s);
            return Cidr.formatIp4(b);
        }
        // 混淆写法：单个 32 位整数（十进制或 0x 十六进制）
        String t = s;
        int radix = 10;
        if (t.startsWith("0x") || t.startsWith("0X")) {
            t = t.substring(2);
            radix = 16;
        }
        try {
            long v = Long.parseLong(t, radix);
            if (v < 0 || v > 0xFFFFFFFFL) {
                throw new NormalizationException("整数 IP 越界: " + raw);
            }
            return ((v >> 24) & 0xFF) + "." + ((v >> 16) & 0xFF) + "."
                    + ((v >> 8) & 0xFF) + "." + (v & 0xFF);
        } catch (NumberFormatException e) {
            throw new NormalizationException("非法 IP（主机名不允许作为 IP 指标）: " + raw);
        }
    }

    /** 规范域名：去末尾点、IDN→ASCII、小写、全角点转点、校验标签。 */
    public String domain(String raw) {
        String s = raw.trim();
        // 容忍误带 URL scheme / 路径 / 端口
        int scheme = s.indexOf("://");
        if (scheme >= 0) {
            s = s.substring(scheme + 3);
        }
        int at = s.indexOf('@');
        if (at >= 0) {
            s = s.substring(at + 1);
        }
        int slash = s.indexOf('/');
        if (slash >= 0) {
            s = s.substring(0, slash);
        }
        int colon = s.indexOf(':');
        if (colon >= 0) {
            s = s.substring(0, colon);
        }
        s = s.replace('．', '.').replace('。', '.');
        if (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty()) {
            throw new NormalizationException("域名为空: " + raw);
        }
        String ascii;
        try {
            ascii = IDN.toASCII(s, IDN.ALLOW_UNASSIGNED).toLowerCase(java.util.Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw new NormalizationException("非法域名（IDN 转换失败）: " + raw);
        }
        String[] labels = ascii.split("\\.", -1);
        if (ascii.length() > 253 || labels.length == 0) {
            throw new NormalizationException("非法域名长度: " + raw);
        }
        for (int i = 0; i < labels.length; i++) {
            String label = labels[i];
            if (label.isEmpty() || label.length() > 63) {
                throw new NormalizationException("非法域名标签（空或过长）: " + raw);
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                throw new NormalizationException("非法域名标签（连字符开头/结尾）: " + raw);
            }
            for (int j = 0; j < label.length(); j++) {
                char c = label.charAt(j);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok) {
                    throw new NormalizationException("非法域名字符: " + raw);
                }
            }
            if (i == labels.length - 1 && !label.startsWith("xn--")) {
                for (int j = 0; j < label.length(); j++) {
                    char c = label.charAt(j);
                    if (c < 'a' || c > 'z') {
                        throw new NormalizationException("非法 TLD（须为字母）: " + raw);
                    }
                }
            }
        }
        return ascii;
    }

    /** 规范 URL。 */
    public String url(String raw) {
        String s = raw.trim();
        URI uri;
        try {
            uri = new URI(s);
        } catch (Exception e) {
            throw new NormalizationException("非法 URL: " + raw);
        }
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new NormalizationException("URL 缺少 scheme: " + raw);
        }
        scheme = scheme.toLowerCase(java.util.Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new NormalizationException("仅支持 http/https URL: " + raw);
        }
        if (uri.getRawAuthority() == null || uri.getHost() == null) {
            throw new NormalizationException("URL 缺少合法主机: " + raw);
        }
        String host = uri.getHost();
        String canonicalHost;
        if (host.startsWith("[")) {
            canonicalHost = "[" + ip(host.substring(1, host.length() - 1)) + "]";
        } else if (host.chars().anyMatch(Character::isDigit) && host.indexOf('.') >= 0
                && looksLikeIp4(host)) {
            canonicalHost = ip(host);
        } else {
            canonicalHost = domain(host);
        }
        int port = uri.getPort();
        if ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443)) {
            port = -1;
        }
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        StringBuilder out = new StringBuilder();
        out.append(scheme).append("://").append(canonicalHost);
        if (port >= 0) {
            out.append(':').append(port);
        }
        out.append(path);
        String query = uri.getRawQuery();
        if (query != null && !query.isEmpty()) {
            String[] pairs = query.split("&");
            String[] sorted = Arrays.stream(pairs).sorted().toArray(String[]::new);
            out.append('?').append(String.join("&", sorted));
        }
        return out.toString();
    }

    private boolean looksLikeIp4(String host) {
        try {
            Cidr.parseIp4(host);
            return true;
        } catch (NormalizationException e) {
            return false;
        }
    }

    /** 规范哈希：小写十六进制并校验长度（md5/sha1/sha256）。 */
    public String hash(String raw) {
        String s = raw.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            s = s.substring(2);
        }
        if (!HEX_HASH.matcher(s).matches()) {
            throw new NormalizationException("哈希含非十六进制字符: " + raw);
        }
        if (s.length() != 32 && s.length() != 40 && s.length() != 64) {
            throw new NormalizationException(
                    "哈希长度非法（仅支持 md5=32/sha1=40/sha256=64）: " + raw);
        }
        return s.toLowerCase(java.util.Locale.ROOT);
    }

    /** 解析网段为规范形式。 */
    public Cidr cidr(String raw) {
        return Cidr.parse(raw);
    }

    /** 域名 b 是否为 a 本身或 a 的子域（入参均为规范域名）。 */
    public boolean isDomainOrSubdomain(String a, String b) {
        return a.equals(b) || b.endsWith("." + a);
    }

    /** 推断自由文本输入属于哪种指标类型；无法识别返回 null。 */
    public IndicatorType detectType(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String s = raw.trim();
        if (HEX_HASH.matcher(s).matches()
                && (s.length() == 32 || s.length() == 40 || s.length() == 64)) {
            return IndicatorType.HASH;
        }
        if (s.contains("://")) {
            return IndicatorType.URL;
        }
        if (s.indexOf(':') < 0 && s.indexOf('.') >= 0 && s.indexOf('/') >= 0) {
            String head = s.substring(0, s.indexOf('/'));
            boolean dottedNumeric = !head.isEmpty()
                    && head.chars().allMatch(c -> (c >= '0' && c <= '9') || c == '.');
            if (dottedNumeric) {
                try {
                    cidr(s);
                    return IndicatorType.CIDR;
                } catch (NormalizationException ignore) {
                    // 落到域名判断
                }
            }
        }
        try {
            ip(s);
            return IndicatorType.IP;
        } catch (NormalizationException ignore) {
            // 继续
        }
        try {
            domain(s);
            return IndicatorType.DOMAIN;
        } catch (NormalizationException ignore) {
            return null;
        }
    }
}
