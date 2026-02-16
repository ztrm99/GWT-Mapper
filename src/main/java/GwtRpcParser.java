import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class GwtRpcParser {
    public record RpcRow(String index, String field, String raw, String resolved) {
    }

    private GwtRpcParser() {
    }

    public static List<RpcRow> parseRequest(String body) {
        List<String> tokens = tokenizePipe(body);
        if (tokens.isEmpty()) {
            return Collections.emptyList();
        }

        List<RpcRow> rows = new ArrayList<>();
        int protocolVersion = parseInt(tokens, 0, -1);
        int flags = parseInt(tokens, 1, -1);
        int stringCount = parseInt(tokens, 2, -1);

        if (tokens.size() > 0) {
            rows.add(new RpcRow("0", "Protocol Version", tokens.get(0), String.valueOf(protocolVersion)));
        }
        if (tokens.size() > 1) {
            rows.add(new RpcRow("1", "Flags", tokens.get(1), String.valueOf(flags)));
        }
        if (tokens.size() > 2) {
            rows.add(new RpcRow("2", "String Table Count", tokens.get(2), String.valueOf(stringCount)));
        }

        List<String> stringTable = new ArrayList<>();
        int i = 3;
        for (int idx = 0; idx < stringCount && i < tokens.size(); idx++, i++) {
            String value = tokens.get(i);
            stringTable.add(value);
            rows.add(new RpcRow(String.valueOf(i), "StringTable[" + (idx + 1) + "]", value, value));
        }

        int payloadPos = 0;
        while (i < tokens.size()) {
            String raw = tokens.get(i);
            String field = inferPayloadField(payloadPos);
            String resolved = resolveRef(raw, stringTable);
            rows.add(new RpcRow(String.valueOf(i), field, raw, resolved));
            i++;
            payloadPos++;
        }

        return rows;
    }

    public static List<RpcRow> parseResponse(String body) {
        String normalized = safe(body).trim();
        if (normalized.isEmpty()) {
            return Collections.emptyList();
        }

        List<RpcRow> rows = new ArrayList<>();
        if (normalized.startsWith("//OK") || normalized.startsWith("//EX")) {
            String status = normalized.startsWith("//OK") ? "OK" : "EXCEPTION";
            rows.add(new RpcRow("0", "Status", status, status));
            String payload = normalized.substring(4).trim();
            rows.addAll(parseBracketPayload(payload, 1));
            return rows;
        }

        List<String> tokens = tokenizePipe(normalized);
        for (int i = 0; i < tokens.size(); i++) {
            String raw = tokens.get(i);
            rows.add(new RpcRow(String.valueOf(i), "Token", raw, raw));
        }
        return rows;
    }

    private static List<RpcRow> parseBracketPayload(String payload, int startIndex) {
        if (payload.isEmpty()) {
            return Collections.emptyList();
        }

        String trimmed = payload;
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }

        List<String> parts = splitTopLevelCsv(trimmed);
        List<RpcRow> rows = new ArrayList<>();
        int idx = startIndex;
        for (String part : parts) {
            String raw = part.trim();
            if (!raw.isEmpty()) {
                rows.add(new RpcRow(String.valueOf(idx), "Payload[" + (idx - startIndex) + "]", raw, unquote(raw)));
                idx++;
            }
        }
        return rows;
    }

    private static List<String> splitTopLevelCsv(String input) {
        List<String> out = new ArrayList<>();
        if (input.isEmpty()) {
            return out;
        }

        int bracketDepth = 0;
        boolean inString = false;
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '"' && (i == 0 || input.charAt(i - 1) != '\\')) {
                inString = !inString;
                current.append(c);
                continue;
            }
            if (!inString) {
                if (c == '[' || c == '{') {
                    bracketDepth++;
                } else if (c == ']' || c == '}') {
                    bracketDepth--;
                } else if (c == ',' && bracketDepth == 0) {
                    out.add(current.toString());
                    current.setLength(0);
                    continue;
                }
            }
            current.append(c);
        }

        if (!current.isEmpty()) {
            out.add(current.toString());
        }

        return out;
    }

    private static String inferPayloadField(int payloadPos) {
        return switch (payloadPos) {
            case 0 -> "Module Base URL Ref";
            case 1 -> "Serialization Policy Ref";
            case 2 -> "Service Interface Ref";
            case 3 -> "Method Ref";
            case 4 -> "Parameter Count";
            default -> "Payload Token";
        };
    }

    private static String resolveRef(String token, List<String> stringTable) {
        Integer value = parseInt(token);
        if (value == null) {
            return token;
        }
        if (value >= 1 && value <= stringTable.size()) {
            return stringTable.get(value - 1);
        }
        return token;
    }

    private static Integer parseInt(String token) {
        try {
            return Integer.parseInt(token.trim());
        } catch (Exception ex) {
            return null;
        }
    }

    private static int parseInt(List<String> tokens, int idx, int defaultValue) {
        if (idx >= tokens.size()) {
            return defaultValue;
        }
        Integer value = parseInt(tokens.get(idx));
        return value == null ? defaultValue : value;
    }

    private static List<String> tokenizePipe(String input) {
        String normalized = safe(input).trim();
        if (normalized.isEmpty()) {
            return Collections.emptyList();
        }
        String[] arr = normalized.split("\\|", -1);
        int limit = arr.length;
        // A trailing pipe is a delimiter terminator in GWT payloads, not a real token.
        if (normalized.endsWith("|") && limit > 0) {
            limit--;
        }
        List<String> out = new ArrayList<>(Math.max(limit, 0));
        for (int i = 0; i < limit; i++) {
            out.add(arr[i]);
        }
        return out;
    }

    private static String unquote(String value) {
        String s = value;
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            return s.substring(1, s.length() - 1).replace("\\\"", "\"");
        }
        return s;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
