import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GwtDetectorTest {

    @Test
    void extractArtifactPathsFindsKnownArtifacts() {
        String body = "script='abc.cache.js'; var x='mod.nocache.js'; policy='service.gwt.rpc';";
        List<String> found = GwtDetector.extractArtifactPaths(body);

        assertEquals(3, found.size());
        assertTrue(found.contains("abc.cache.js"));
        assertTrue(found.contains("mod.nocache.js"));
        assertTrue(found.contains("service.gwt.rpc"));
    }

    @Test
    void looksLikeGwtRpcPayloadByHeaders() {
        boolean result = GwtDetector.looksLikeGwtRpcPayload(
                "hello",
                List.of("Content-Type: text/x-gwt-rpc; charset=UTF-8")
        );
        assertTrue(result);
    }

    @Test
    void looksLikeGwtRpcPayloadByBodyPattern() {
        assertTrue(GwtDetector.looksLikeGwtRpcPayload("7|0|4|a|b|c|d|", List.of()));
        assertFalse(GwtDetector.looksLikeGwtRpcPayload("not rpc", List.of()));
    }
}
