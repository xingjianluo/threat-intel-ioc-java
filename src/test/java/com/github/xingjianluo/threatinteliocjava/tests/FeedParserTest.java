package com.github.xingjianluo.threatinteliocjava.tests;

import com.github.xingjianluo.threatinteliocjava.ingest.CsvFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.FeedParseException;
import com.github.xingjianluo.threatinteliocjava.ingest.JsonlFeedParser;
import com.github.xingjianluo.threatinteliocjava.ingest.ParsedBatch;
import com.github.xingjianluo.threatinteliocjava.model.RejectionCode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 解析器测试：好行解析、坏行逐行拒绝（MALFORMED_FORMAT），坏表头为文件级异常。
 */
class FeedParserTest {

    private final JsonlFeedParser jsonl = new JsonlFeedParser();
    private final CsvFeedParser csv = new CsvFeedParser();

    @Test
    void jsonlParsesValidAndRejectsBadLinesWithReasons() {
        String content = """
                {"type": "ip", "value": "1.1.1.1", "severity": "low"}

                not json
                {"type": "ip"}
                {"type": "ip", "value": 5}
                {"type": "domain", "value": "ok.example"}
                """;
        ParsedBatch batch = jsonl.parse(content);
        assertEquals(2, batch.entries().size());
        assertEquals(3, batch.rejected().size());
        assertTrue(batch.rejected().stream()
                .allMatch(r -> r.code() == RejectionCode.MALFORMED_FORMAT));
        // 拒绝条目必须带行号，原因可区分、可定位
        assertTrue(batch.rejected().get(0).rawLine().startsWith("L3"));
        assertTrue(batch.rejected().get(0).detail().contains("invalid JSON"));
        assertTrue(batch.rejected().get(1).detail().contains("missing required"));
    }

    @Test
    void csvParsesQuotedFieldsCommentsAndRejectsBadRows() {
        String content = """
                # comment
                type,value,severity
                ip,"1.2.3.4",HIGH
                ip,"5.6.7.8",HIGH,EXTRA
                domain,"unterminated
                domain,,low
                domain,good.example,medium
                """;
        ParsedBatch batch = csv.parse(content);
        assertEquals(2, batch.entries().size());
        assertEquals(3, batch.rejected().size());
        assertEquals("1.2.3.4", batch.entries().get(0).rawValue());
        assertEquals("good.example", batch.entries().get(1).rawValue());
        assertTrue(batch.rejected().stream()
                .allMatch(r -> r.code() == RejectionCode.MALFORMED_FORMAT));
    }

    @Test
    void csvMissingRequiredHeaderIsFileLevelError() {
        FeedParseException ex = assertThrows(FeedParseException.class,
                () -> csv.parse("value,severity\n1.1.1.1,low\n"));
        assertEquals(RejectionCode.MALFORMED_FORMAT, ex.code());
    }

    @Test
    void csvEmptyFileIsFileLevelError() {
        assertThrows(FeedParseException.class, () -> csv.parse("# only comment\n"));
    }
}
