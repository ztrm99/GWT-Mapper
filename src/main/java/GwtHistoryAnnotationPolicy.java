import java.util.LinkedHashSet;
import java.util.Set;

public final class GwtHistoryAnnotationPolicy {
    static final String NOTE_RPC_REQUEST = "GWT RPC request";
    static final String NOTE_CACHE_FILE = "GWT RPC cache file";

    private GwtHistoryAnnotationPolicy() {
    }

    static String detectNote(String requestPath, boolean looksLikeRpcRequest) {
        Set<String> parts = new LinkedHashSet<>();
        if (looksLikeRpcRequest) {
            parts.add(NOTE_RPC_REQUEST);
        }
        if (safe(requestPath).toLowerCase().contains(".cache.js")) {
            parts.add(NOTE_CACHE_FILE);
        }
        if (parts.isEmpty()) {
            return "";
        }
        return String.join(" | ", parts);
    }

    static String mergeNote(String existing, String added) {
        Set<String> parts = new LinkedHashSet<>();
        addParts(parts, existing);
        addParts(parts, added);
        if (parts.isEmpty()) {
            return "";
        }
        return String.join(" | ", parts);
    }

    private static void addParts(Set<String> parts, String source) {
        String value = safe(source).trim();
        if (value.isEmpty()) {
            return;
        }
        for (String p : value.split("\\|")) {
            String token = safe(p).trim();
            if (!token.isEmpty()) {
                parts.add(token);
            }
        }
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
