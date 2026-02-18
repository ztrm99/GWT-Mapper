import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GwtRpcRequestEditSupportTest {
    @Test
    void isApplySupportedOnlyForEditableSupportedTools() {
        assertTrue(GwtRpcRequestEditSupport.isApplySupported(false, true));
        assertFalse(GwtRpcRequestEditSupport.isApplySupported(true, true));
        assertFalse(GwtRpcRequestEditSupport.isApplySupported(false, false));
        assertFalse(GwtRpcRequestEditSupport.isApplySupported(true, false));
    }

    @Test
    void rebuildBodyFromRowsReplacesEditedTokensByIndex() {
        String body = "7|0|6|http://target/app/|ABCDEF|com.test.UserService|getUser|java.lang.String/2004016611|42|1|2|3|4|1|5|6|";
        Optional<GwtRpcSemanticParser.SemanticRequest> parsed = GwtRpcSemanticParser.parseRequest(body);
        assertTrue(parsed.isPresent());

        List<GwtRpcParser.RpcRow> rows = new ArrayList<>(GwtRpcParser.parseRequest(body));
        replaceRawAtIndex(rows, "3", "http://edited/app/");
        replaceRawAtIndex(rows, "6", "getUserById");

        List<String> originalTokens = new ArrayList<>();
        for (GwtRpcSemanticParser.TokenSpan t : parsed.get().tokens()) {
            originalTokens.add(t.text());
        }

        String rebuilt = GwtRpcRequestEditSupport.rebuildBodyFromRows(rows, originalTokens, parsed.get().trailingDelimiter());
        assertEquals("7|0|6|http://edited/app/|ABCDEF|com.test.UserService|getUserById|java.lang.String/2004016611|42|1|2|3|4|1|5|6|", rebuilt);
    }

    @Test
    void rebuildBodyFromRowsSanitizesTokenDelimiters() {
        List<GwtRpcParser.RpcRow> rows = List.of(
                new GwtRpcParser.RpcRow("0", "Protocol Version", "7", "7"),
                new GwtRpcParser.RpcRow("1", "Flags", "0", "0"),
                new GwtRpcParser.RpcRow("2", "String Table Count", "1", "1"),
                new GwtRpcParser.RpcRow("3", "StringTable[1]", "A|B", "A|B")
        );
        String rebuilt = GwtRpcRequestEditSupport.rebuildBodyFromRows(rows, List.of("7", "0", "1", "A"), true);
        assertEquals("7|0|1|A_B|", rebuilt);
    }

    private static void replaceRawAtIndex(List<GwtRpcParser.RpcRow> rows, String tokenIndex, String replacement) {
        for (int i = 0; i < rows.size(); i++) {
            GwtRpcParser.RpcRow row = rows.get(i);
            if (tokenIndex.equals(row.index())) {
                rows.set(i, new GwtRpcParser.RpcRow(row.index(), row.field(), replacement, row.resolved()));
                return;
            }
        }
    }

}
