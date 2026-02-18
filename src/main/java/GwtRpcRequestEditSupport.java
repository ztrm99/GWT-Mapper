import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;

import java.util.ArrayList;
import java.util.List;

public final class GwtRpcRequestEditSupport {
    private GwtRpcRequestEditSupport() {
    }

    public static boolean isApplySupported(EditorCreationContext creationContext) {
        if (creationContext == null) {
            return false;
        }
        boolean readOnly = creationContext.editorMode() == EditorMode.READ_ONLY;
        if (creationContext.toolSource() == null) {
            return false;
        }
        boolean supportedTool = creationContext.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER);
        return isApplySupported(readOnly, supportedTool);
    }

    static boolean isApplySupported(boolean readOnly, boolean supportedTool) {
        return !readOnly && supportedTool;
    }

    public static String rebuildBodyFromRows(
            List<GwtRpcParser.RpcRow> rows,
            List<String> originalTokens,
            boolean trailingDelimiter
    ) {
        List<String> rebuilt = new ArrayList<>(originalTokens);
        for (GwtRpcParser.RpcRow row : rows) {
            int idx = parseInt(row.index(), -1);
            if (idx < 0 || idx >= rebuilt.size()) {
                continue;
            }
            rebuilt.set(idx, sanitizeToken(row.raw()));
        }
        String out = String.join("|", rebuilt);
        if (trailingDelimiter) {
            return out + "|";
        }
        return out;
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(safe(value).trim());
        } catch (Exception ex) {
            return fallback;
        }
    }

    private static String sanitizeToken(String value) {
        return safe(value).replace("|", "_");
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
