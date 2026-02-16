import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GwtRpcSemanticParserTest {

    @Test
    void parseRequestExtractsMethodAndParameters() {
        String body = "7|0|6|http://target/app/|ABCDEF|com.test.UserService|getUser|java.lang.String/2004016611|42|1|2|3|4|1|5|6|";
        Optional<GwtRpcSemanticParser.SemanticRequest> parsed = GwtRpcSemanticParser.parseRequest(body);

        assertTrue(parsed.isPresent());
        GwtRpcSemanticParser.SemanticRequest req = parsed.get();
        assertEquals("com.test.UserService::getUser", req.methodKey());
        assertEquals(1, req.parameters().size());
        assertEquals("42", req.parameters().get(0).valueResolved());
        assertEquals(8, req.parameters().get(0).mutationTokenIndex());
    }

    @Test
    void parseRequestPreservesEmptyStringTableTokens() {
        String body = "7|0|6|http://target/app/||com.test.UserService|getUser|java.lang.String/2004016611|42|1|2|3|4|1|5|6|";
        Optional<GwtRpcSemanticParser.SemanticRequest> parsed = GwtRpcSemanticParser.parseRequest(body);

        assertTrue(parsed.isPresent());
        GwtRpcSemanticParser.SemanticRequest req = parsed.get();
        assertEquals("", req.stringTable().get(1));
        assertTrue(req.trailingDelimiter());
    }

    @Test
    void rebuildBodyReplacesSingleTokenAndKeepsTerminalDelimiter() {
        String body = "7|0|4|a|b|c|d|1|2|3|4|0|";
        Optional<GwtRpcSemanticParser.SemanticRequest> parsed = GwtRpcSemanticParser.parseRequest(body);
        assertTrue(parsed.isPresent());

        String rebuilt = GwtRpcSemanticParser.rebuildBody(parsed.get(), 4, "X");
        assertTrue(rebuilt.endsWith("|"));
        assertEquals("7|0|4|a|X|c|d|1|2|3|4|0|", rebuilt);
    }

    @Test
    void parseRequestReturnsEmptyForNonRpcBody() {
        assertFalse(GwtRpcSemanticParser.parseRequest("not-rpc-data").isPresent());
    }
}
