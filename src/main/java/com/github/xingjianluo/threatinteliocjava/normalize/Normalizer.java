package com.github.xingjianluo.threatinteliocjava.normalize;

import com.github.xingjianluo.threatinteliocjava.model.IndicatorType;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import com.github.xingjianluo.threatinteliocjava.model.Severity;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 类型/值归一化组件：把各种等价/混淆写法收敛为唯一规范值。
 *
 * <p>规范值规则：
 * <ul>
 *   <li>IPV4：点分十进制；支持整段十进制/八进制(0前缀)/十六进制(0x)混淆、
 *       32位整数(十进制或0x)、2段/3段混合位宽、末尾 :端口、方括号；支持 CIDR，
 *       输出时主机位清零并校验位宽 0..32。</li>
 *   <li>DOMAIN：小写、去根点、去前导通配 "*."；标签合法且至少含一个点。</li>
 *   <li>URL：补 http:// 方案、主机小写、去默认端口 80/443、去 fragment。</li>
 *   <li>HASH：小写十六进制，按长度区分 MD5(32)/SHA1(40)/SHA256(64)。</li>
 *   <li>EMAIL：小写去空白。</li>
 * </ul>
 */
@Component
public class Normalizer {

    private static final Pattern HEX32 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern HEX40 = Pattern.compile("[0-9a-f]{40}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern DOMAIN_LABEL =
            Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    private static final Pattern EMAIL =
            Pattern.compile("[^@\\s]+@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+");

    private static final Map<String, IndicatorType> TYPE_ALIASES = Map.ofEntries(
            Map.entry("ip", IndicatorType.IPV4),
            Map.entry("ipv4", IndicatorType.IPV4),
            Map.entry("ip4", IndicatorType.IPV4),
            Map.entry("ipv4-addr", IndicatorType.IPV4),
            Map.entry("ip-address", IndicatorType.IPV4),
            Map.entry("addr", IndicatorType.IPV4),
            Map.entry("domain", IndicatorType.DOMAIN),
            Map.entry("domain-name", IndicatorType.DOMAIN),
            Map.entry("hostname", IndicatorType.DOMAIN),
            Map.entry("fqdn", IndicatorType.DOMAIN),
            Map.entry("url", IndicatorType.URL),
            Map.entry("uri", IndicatorType.URL),
            Map.entry("md5", IndicatorType.HASH_MD5),
            Map.entry("hash-md5", IndicatorType.HASH_MD5),
            Map.entry("sha1", IndicatorType.HASH_SHA1),
            Map.entry("hash-sha1", IndicatorType.HASH_SHA1),
            Map.entry("sha256", IndicatorType.HASH_SHA256),
            Map.entry("hash-sha256", IndicatorType.HASH_SHA256),
            Map.entry("email", IndicatorType.EMAIL),
            Map.entry("email-addr", IndicatorType.EMAIL),
            Map.entry("email-address", IndicatorType.EMAIL),
            Map.entry("mail", IndicatorType.EMAIL));

    private static final Set<String> KNOWN_SEVERITIES =
            Set.of("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO");

    /** 把源中的类型字符串映射为统一类型；无法识别时抛 UNSUPPORTED_TYPE。 */
    public IndicatorType normalizeType(String rawType) {
        if (rawType == null || rawType.isBlank()) {
            throw new NormalizationException(RejectionCode.MALFORMED_FORMAT,
                    "missing indicator type");
        }
        String key = rawType.trim().toLowerCase(Locale.ROOT);
        IndicatorType type = TYPE_ALIASES.get(key);
        if (type == null) {
            throw new NormalizationException(RejectionCode.UNSUPPORTED_TYPE,
                    "unsupported indicator type: '" + rawType + "'");
        }
        return type;
    }

    /** 严重度归一：空白按 UNKNOWN；无法识别的非空值按 INVALID_VALUE 拒绝（可解释、不静默）。 */
    public Severity normalizeSeverity(String rawSeverity) {
        if (rawSeverity == null || rawSeverity.isBlank()) {
            return Severity.UNKNOWN;
        }
        String key = rawSeverity.trim().toUpperCase(Locale.ROOT);
        if (!KNOWN_SEVERITIES.contains(key)) {
            throw new NormalizationException(RejectionCode.INVALID_VALUE,
                    "unsupported severity: '" + rawSeverity + "'");
        }
        return "INFO".equals(key) ? Severity.LOW : Severity.valueOf(key);
    }

    /** 归一化一条完整输入（类型 + 值 + 严重度）。 */
    public NormalizedRaw normalize(String rawType, String rawValue, String rawSeverity) {
        IndicatorType type = normalizeType(rawType);
        String value = normalizeValue(type, rawValue);
        return new NormalizedRaw(type, value, rawValue == null ? value : rawValue.trim(),
                normalizeSeverity(rawSeverity));
    }

    /**
     * 归一化具体指标值。
     *
     * @param type 已归一的类型
     * @param raw  原始值
     * @return 规范值
     */
    public String normalizeValue(IndicatorType type, String raw) {
        if (raw == null || raw.isBlank()) {
            throw new NormalizationException(RejectionCode.MALFORMED_FORMAT,
                    "empty indicator value for type " + type);
        }
        return switch (type) {
            case IPV4 -> normalizeIpv4(raw);
            case DOMAIN -> normalizeDomain(raw);
            case URL -> normalizeUrl(raw);
            case HASH_MD5 -> normalizeHash(raw, 32, HEX32, type);
            case HASH_SHA1 -> normalizeHash(raw, 40, HEX40, type);
            case HASH_SHA256 -> normalizeHash(raw, 64, HEX64, type);
            case EMAIL -> normalizeEmail(raw);
        };
    }

    /**
     * 查询未声明类型时的确定性推断。无法判定抛 MALFORMED_FORMAT，
     * 调用方也可显式传 type 避免歧义。
     */
    public IndicatorType inferType(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new NormalizationException(RejectionCode.MALFORMED_FORMAT, "empty query value");
        }
        String v = rawValue.trim();
        String lower = v.toLowerCase(Locale.ROOT);
        if (v.startsWith("http://") || v.startsWith("https://") || v.matches("\\w+://.*")) {
            return IndicatorType.URL;
        }
        String noScheme = lower.replaceFirst("^//", "");
        if (EMAIL.matcher(lower.replaceAll("\\s", "")).matches()) {
            return IndicatorType.EMAIL;
        }
        if (lower.matches("[0-9a-f]{32}")) {
            return IndicatorType.HASH_MD5;
        }
        if (lower.matches("[0-9a-f]{40}")) {
            return IndicatorType.HASH_SHA1;
        }
        if (lower.matches("[0-9a-f]{64}")) {
            return IndicatorType.HASH_SHA256;
        }
        if (looksLikeIpv4(noScheme)) {
            return IndicatorType.IPV4;
        }
        if (looksLikeDomain(noScheme)) {
            return IndicatorType.DOMAIN;
        }
        throw new NormalizationException(RejectionCode.MALFORMED_FORMAT,
                "cannot infer type for input: '" + rawValue + "'");
    }

    // ------------------------------------------------------------------
    // IPV4
    // ------------------------------------------------------------------

    /** 归一化为 "a.b.c.d" 或 "a.b.c.d/p"（CIDR 主机位清零）。 */
    public String normalizeIpv4(String raw) {
        String v = raw.trim().toLowerCase(Locale.ROOT);
        int slash = v.indexOf('/');
        String hostPart;
        Integer prefix = null;
        if (slash >= 0) {
            hostPart = v.substring(0, slash);
            String prefixText = v.substring(slash + 1);
            try {
                prefix = Integer.parseInt(prefixText.trim());
            } catch (NumberFormatException e) {
                throw invalid("invalid CIDR prefix: '" + raw + "'");
            }
            if (prefix < 0 || prefix > 32) {
                throw invalid("CIDR prefix out of range 0..32: '" + raw + "'");
            }
        } else {
            hostPart = v;
        }
        long ip = parseIpv4Host(hostPart, raw);
        if (prefix != null) {
            long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            long network = ip & mask;
            return formatIpv4(network) + "/" + prefix;
        }
        return formatIpv4(ip);
    }

    /**
     * 解析 IPv4 主机写法，支持：
     * 4 段（每段十/八/十六进制）、3 段(末段16位)、2 段(末段24位)、1 段(32位整数)，
     * 末尾 :端口剥离、方括号剥离。不触发任何 DNS 解析。
     */
    private long parseIpv4Host(String hostPart, String original) {
        String h = hostPart;
        if (h.startsWith("[")) {
            int end = h.indexOf(']');
            if (end < 0) {
                throw invalid("invalid ipv4 bracket: '" + original + "'");
            }
            String after = h.substring(end + 1);
            h = h.substring(1, end);
            if (!after.isEmpty() && !(after.startsWith(":"))) {
                throw invalid("invalid ipv4 bracket suffix: '" + original + "'");
            }
        }
        int colon = h.indexOf(':');
        if (colon >= 0) {
            h = h.substring(0, colon);
        }
        if (h.isEmpty()) {
            throw invalid("invalid ipv4: '" + original + "'");
        }
        String[] parts = h.split("\\.", -1);
        try {
            return switch (parts.length) {
                case 1 -> {
                    long value = parseUnsignedSegment(parts[0], 32);
                    yield value & 0xFFFFFFFFL;
                }
                case 2 -> combine(new long[]{
                        parseUnsignedSegment(parts[0], 8),
                        parseUnsignedSegment(parts[1], 24)}, new int[]{8, 24});
                case 3 -> combine(new long[]{
                        parseUnsignedSegment(parts[0], 8),
                        parseUnsignedSegment(parts[1], 8),
                        parseUnsignedSegment(parts[2], 16)}, new int[]{8, 8, 16});
                case 4 -> combine(new long[]{
                        parseUnsignedSegment(parts[0], 8),
                        parseUnsignedSegment(parts[1], 8),
                        parseUnsignedSegment(parts[2], 8),
                        parseUnsignedSegment(parts[3], 8)}, new int[]{8, 8, 8, 8});
                default -> throw invalid("invalid ipv4 (too many parts): '" + original + "'");
            };
        } catch (IllegalArgumentException e) {
            throw invalid("invalid ipv4: '" + original + "' (" + e.getMessage() + ")");
        }
    }

    private long combine(long[] values, int[] bits) {
        long result = 0L;
        int shift = 0;
        for (int j = 0; j < bits.length; j++) {
            shift += bits[j];
        }
        for (int i = 0; i < values.length; i++) {
            long max = bits[i] == 32 ? 0xFFFFFFFFL : (1L << bits[i]) - 1;
            if (values[i] > max) {
                throw new IllegalArgumentException("segment value out of range");
            }
            shift -= bits[i];
            result |= (values[i] << shift) & 0xFFFFFFFFL;
        }
        return result & 0xFFFFFFFFL;
    }

    /** 解析单段：0x 前缀十六进制；0 开头（且多于一位、非 "0"）八进制；否则十进制。 */
    private long parseUnsignedSegment(String segment, int maxBits) {
        if (segment.isEmpty()) {
            throw new NumberFormatException("empty segment");
        }
        long value;
        if (segment.startsWith("0x") || segment.startsWith("0X")) {
            value = Long.parseUnsignedLong(segment.substring(2), 16);
        } else if (segment.length() > 1 && segment.startsWith("0")) {
            value = Long.parseUnsignedLong(segment, 8);
        } else {
            value = Long.parseUnsignedLong(segment, 10);
        }
        long max = maxBits == 32 ? 0xFFFFFFFFL : (1L << maxBits) - 1;
        if (value < 0 || value > max) {
            throw new NumberFormatException("segment overflow");
        }
        return value;
    }

    /** 点分十进制 -> 32 位无符号长整型（输入必须已是规范点分形式）。 */
    public long ipv4ToLong(String dotted) {
        String[] parts = dotted.split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("not a canonical ipv4: " + dotted);
        }
        long result = 0L;
        for (String p : parts) {
            long octet = Long.parseLong(p);
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("octet out of range: " + dotted);
            }
            result = ((result << 8) | octet) & 0xFFFFFFFFL;
        }
        return result;
    }

    public static String formatIpv4(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "."
                + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    /** 规范值是否为 CIDR。 */
    public boolean isCidr(String canonicalValue) {
        return canonicalValue.indexOf('/') >= 0;
    }

    private boolean looksLikeIpv4(String candidate) {
        String stripped = candidate.replaceFirst("[:/].*$", "");
        if (!stripped.matches("[0-9a-fx.]+")) {
            return false;
        }
        try {
            parseIpv4Host(stripped, stripped);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // DOMAIN
    // ------------------------------------------------------------------

    public String normalizeDomain(String raw) {
        String v = raw.trim().toLowerCase(Locale.ROOT);
        if (v.startsWith("[") && v.endsWith("]")) {
            v = v.substring(1, v.length() - 1);
        }
        if (v.endsWith(".")) {
            v = v.substring(0, v.length() - 1);
        }
        if (v.startsWith("*.")) {
            v = v.substring(2);
        }
        if (looksLikeIpv4(v)) {
            throw invalid("value looks like an ipv4 address, not a domain: '" + raw + "'");
        }
        if (!looksLikeDomain(v)) {
            throw invalid("invalid domain: '" + raw + "'");
        }
        return v;
    }

    private boolean looksLikeDomain(String v) {
        if (v == null || v.isEmpty() || v.startsWith(".") || v.endsWith(".")) {
            return false;
        }
        if (v.contains("..") || v.length() > 253) {
            return false;
        }
        String[] labels = v.split("\\.", -1);
        if (labels.length < 2) {
            return false;
        }
        for (String label : labels) {
            if (!DOMAIN_LABEL.matcher(label).matches()) {
                return false;
            }
        }
        return true;
    }

    /** 子域判定：child 等于 parent 或以 ".parent" 结尾（两者均为规范域名）。 */
    public boolean isSubDomainOrSame(String child, String parent) {
        return child.equals(parent) || child.endsWith("." + parent);
    }

    // ------------------------------------------------------------------
    // URL
    // ------------------------------------------------------------------

    public String normalizeUrl(String raw) {
        String v = raw.trim();
        if (!v.contains("://")) {
            v = "http://" + v;
        }
        int schemeEnd = v.indexOf("://");
        String scheme = v.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw invalid("unsupported url scheme: '" + raw + "'");
        }
        String rest = v.substring(schemeEnd + 3);
        int hashIdx = rest.indexOf('#');
        if (hashIdx >= 0) {
            rest = rest.substring(0, hashIdx);
        }
        String authority;
        String pathQuery;
        int slashIdx = rest.indexOf('/');
        if (slashIdx >= 0) {
            authority = rest.substring(0, slashIdx);
            pathQuery = rest.substring(slashIdx);
        } else {
            authority = rest;
            pathQuery = "";
        }
        String host;
        String nonDefaultPort = "";
        if (authority.startsWith("[") && authority.contains("]")) {
            int end = authority.indexOf(']');
            host = authority.substring(1, end);
            String afterBracket = authority.substring(end + 1);
            if (afterBracket.startsWith(":")) {
                nonDefaultPort = afterBracket;
            }
        } else {
            int at = authority.indexOf('@');
            String hostPort = at >= 0 ? authority.substring(at + 1) : authority;
            int colon = hostPort.indexOf(':');
            if (colon >= 0) {
                String portText = hostPort.substring(colon + 1);
                int port;
                try {
                    port = Integer.parseInt(portText);
                } catch (NumberFormatException e) {
                    throw invalid("invalid url port: '" + raw + "'");
                }
                host = hostPort.substring(0, colon);
                if (!((scheme.equals("http") && port == 80)
                        || (scheme.equals("https") && port == 443))) {
                    nonDefaultPort = ":" + port;
                }
            } else {
                host = hostPort;
            }
        }
        String canonicalHost;
        if (looksLikeIpv4(host)) {
            canonicalHost = normalizeIpv4(host);
        } else {
            canonicalHost = normalizeDomain(host);
        }
        return scheme + "://" + canonicalHost + nonDefaultPort + pathQuery;
    }

    /** 规范 URL 的主机部分（供跨类型匹配：URL 对 DOMAIN/IPV4 指标）。 */
    public String hostOfUrl(String canonicalUrl) {
        String rest = canonicalUrl.substring(canonicalUrl.indexOf("://") + 3);
        int slash = rest.indexOf('/');
        String authority = slash >= 0 ? rest.substring(0, slash) : rest;
        if (authority.startsWith("[")) {
            return authority.substring(1, authority.indexOf(']'));
        }
        int colon = authority.indexOf(':');
        return colon >= 0 ? authority.substring(0, colon) : authority;
    }

    // ------------------------------------------------------------------
    // HASH / EMAIL
    // ------------------------------------------------------------------

    private String normalizeHash(String raw, int expectedLen, Pattern pattern, IndicatorType type) {
        String v = raw.trim().toLowerCase(Locale.ROOT);
        if (!pattern.matcher(v).matches()) {
            throw invalid("invalid " + type + " (expected " + expectedLen
                    + " lowercase hex chars): '" + raw + "'");
        }
        return v;
    }

    private String normalizeEmail(String raw) {
        String v = raw.trim().toLowerCase(Locale.ROOT);
        if (!EMAIL.matcher(v).matches() || v.length() > 254) {
            throw invalid("invalid email: '" + raw + "'");
        }
        return v;
    }

    private NormalizationException invalid(String message) {
        return new NormalizationException(RejectionCode.INVALID_VALUE, message);
    }
}
