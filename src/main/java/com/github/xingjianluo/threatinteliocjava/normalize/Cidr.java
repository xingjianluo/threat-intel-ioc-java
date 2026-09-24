package com.github.xingjianluo.threatinteliocjava.normalize;

/**
 * 一个规范化的 IPv4/IPv6 网段（网络地址 + 前缀长度），支持包含判定。
 * 网络地址统一为压缩规范写法，解析过程不发生任何 DNS 查询。
 */
public record Cidr(String networkAddress, int prefixLength) {

    /** 解析 a.b.c.d/n 或 v6/n，返回网络地址被掩码后的规范网段。 */
    public static Cidr parse(String raw) {
        if (raw == null) {
            throw new NormalizationException("cidr 为空");
        }
        String s = raw.trim();
        int slash = s.lastIndexOf('/');
        if (slash < 0) {
            throw new NormalizationException("cidr 缺少前缀长度: " + raw);
        }
        String addrPart = s.substring(0, slash);
        String prefixPart = s.substring(slash + 1);
        int prefix;
        try {
            prefix = Integer.parseInt(prefixPart.trim());
        } catch (NumberFormatException e) {
            throw new NormalizationException("cidr 前缀长度不是数字: " + raw);
        }
        boolean v6 = addrPart.indexOf(':') >= 0;
        int maxPrefix = v6 ? 128 : 32;
        if (prefix < 0 || prefix > maxPrefix) {
            throw new NormalizationException("cidr 前缀越界: " + raw);
        }
        byte[] bytes;
        if (v6) {
            bytes = parseIp6(addrPart);
        } else {
            bytes = parseIp4(addrPart);
        }
        mask(bytes, prefix);
        String network = v6 ? formatIp6(bytes) : formatIp4(bytes);
        return new Cidr(network, prefix);
    }

    /** 给定规范 IP 是否落在本网段内。 */
    public boolean contains(String ip) {
        try {
            boolean v6 = networkAddress.indexOf(':') >= 0;
            byte[] ipBytes = v6 ? parseIp6(ip) : parseIp4(ip);
            byte[] netBytes = v6 ? parseIp6(networkAddress) : parseIp4(networkAddress);
            if (ipBytes.length != netBytes.length) {
                return false;
            }
            int full = prefixLength / 8;
            int rem = prefixLength % 8;
            for (int i = 0; i < full; i++) {
                if (ipBytes[i] != netBytes[i]) {
                    return false;
                }
            }
            if (rem > 0 && full < ipBytes.length) {
                int m = 0xFF << (8 - rem);
                if ((ipBytes[full] & m) != (netBytes[full] & m)) {
                    return false;
                }
            }
            return true;
        } catch (NormalizationException e) {
            return false;
        }
    }

    private static void mask(byte[] bytes, int prefix) {
        int total = bytes.length * 8;
        for (int bit = prefix; bit < total; bit++) {
            int idx = bit / 8;
            int b = 7 - (bit % 8);
            bytes[idx] &= (byte) ~(1 << b);
        }
    }

    static byte[] parseIp4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            throw new NormalizationException("非法 IPv4: " + s);
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) {
                throw new NormalizationException("非法 IPv4 段: " + s);
            }
            for (int j = 0; j < p.length(); j++) {
                char c = p.charAt(j);
                if (c < '0' || c > '9') {
                    throw new NormalizationException("IPv4 含非数字: " + s);
                }
            }
            int v = Integer.parseInt(p);
            if (v > 255) {
                throw new NormalizationException("IPv4 段越界: " + s);
            }
            out[i] = (byte) v;
        }
        return out;
    }

    static byte[] parseIp6(String s) {
        if (s == null || s.isEmpty()) {
            throw new NormalizationException("非法 IPv6: 空");
        }
        // 支持内嵌 IPv4 写法（如 ::ffff:192.0.2.1）：先把尾部点分四段转为两个 hextet
        int dot = s.indexOf('.');
        if (dot >= 0) {
            int colonBeforeDot = s.lastIndexOf(':', dot);
            int colonAfterDot = s.indexOf(':', dot);
            if (colonBeforeDot < 0 || colonAfterDot >= 0) {
                throw new NormalizationException("非法 IPv6 内嵌地址: " + s);
            }
            String v4 = s.substring(colonBeforeDot + 1);
            byte[] v4bytes = parseIp4(v4);
            String hex = String.format(java.util.Locale.ROOT, "%02x%02x:%02x%02x",
                    v4bytes[0] & 0xFF, v4bytes[1] & 0xFF,
                    v4bytes[2] & 0xFF, v4bytes[3] & 0xFF);
            s = s.substring(0, colonBeforeDot + 1) + hex;
        }
        int dc = s.indexOf("::");
        String head;
        String tail = "";
        if (dc >= 0) {
            if (s.indexOf("::", dc + 1) >= 0) {
                throw new NormalizationException("非法 IPv6，含多个 :: : " + s);
            }
            head = s.substring(0, dc);
            tail = s.substring(dc + 2);
        } else {
            head = s;
        }
        String[] headParts = head.isEmpty() ? new String[0] : head.split(":", -1);
        String[] tailParts = tail.isEmpty() ? new String[0] : tail.split(":", -1);
        int missing = 8 - headParts.length - tailParts.length;
        if (dc < 0) {
            if (missing != 0) {
                throw new NormalizationException("非法 IPv6 段数: " + s);
            }
        } else if (missing < 0) {
            throw new NormalizationException("非法 IPv6 段过多: " + s);
        }
        byte[] out = new byte[16];
        int pos = 0;
        pos = putHextets(out, pos, headParts, s);
        pos += missing * 2;
        putHextets(out, pos, tailParts, s);
        return out;
    }

    private static int putHextets(byte[] out, int pos, String[] parts, String original) {
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 4) {
                throw new NormalizationException("非法 IPv6 hextet: " + original);
            }
            for (int j = 0; j < p.length(); j++) {
                char c = p.charAt(j);
                boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) {
                    throw new NormalizationException("IPv6 含非十六进制字符: " + original);
                }
            }
            int v = Integer.parseInt(p, 16);
            out[pos++] = (byte) (v >> 8);
            out[pos++] = (byte) v;
        }
        return pos;
    }

    static String formatIp4(byte[] b) {
        return (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF);
    }

    static String formatIp6(byte[] bytes) {
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((bytes[2 * i] & 0xFF) << 8) | (bytes[2 * i + 1] & 0xFF);
        }
        // 找最长的连续零段（长度 >=2），取第一个最长序列，压缩为 ::
        int bestStart = -1;
        int bestLen = 0;
        int runStart = -1;
        for (int i = 0; i <= 8; i++) {
            if (i < 8 && groups[i] == 0) {
                if (runStart < 0) {
                    runStart = i;
                }
            } else if (runStart >= 0) {
                int len = i - runStart;
                if (len >= 2 && len > bestLen) {
                    bestLen = len;
                    bestStart = runStart;
                }
                runStart = -1;
            }
        }
        StringBuilder sb = new StringBuilder();
        if (bestStart < 0) {
            for (int i = 0; i < 8; i++) {
                if (i > 0) {
                    sb.append(':');
                }
                sb.append(Integer.toHexString(groups[i]));
            }
        } else {
            int bestEnd = bestStart + bestLen;
            for (int i = 0; i < bestStart; i++) {
                if (i > 0) {
                    sb.append(':');
                }
                sb.append(Integer.toHexString(groups[i]));
            }
            sb.append("::");
            for (int i = bestEnd; i < 8; i++) {
                if (i > bestEnd) {
                    sb.append(':');
                }
                sb.append(Integer.toHexString(groups[i]));
            }
        }
        return sb.toString();
    }
}
