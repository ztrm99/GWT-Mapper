import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public final class GwtRpcSemanticParser {
    private GwtRpcSemanticParser() {
    }

    public record TokenSpan(int index, int start, int end, String text) {
    }

    public record ParameterInfo(
            int index,
            String typeRaw,
            String typeResolved,
            String valueRaw,
            String valueResolved,
            int valueTokenIndex,
            int mutationTokenIndex
    ) {
    }

    public record SemanticRequest(
            int protocolVersion,
            int flags,
            List<TokenSpan> tokens,
            boolean trailingDelimiter,
            List<String> stringTable,
            String moduleBase,
            String serializationPolicy,
            String serviceInterface,
            String methodName,
            int paramCount,
            List<ParameterInfo> parameters
    ) {
        public String methodKey() {
            if (!safe(serviceInterface).isEmpty() && !safe(methodName).isEmpty()) {
                return serviceInterface + "::" + methodName;
            }
            return safe(methodName);
        }
    }

    public static Optional<SemanticRequest> parseRequest(String body) {
        List<TokenSpan> tokens = tokenizePipeWithOffsets(safe(body));
        if (tokens.size() < 8) {
            return Optional.empty();
        }

        int protocol = parseInt(tokens.get(0).text(), -1);
        int flags = parseInt(tokens.get(1).text(), -1);
        int stringCount = parseInt(tokens.get(2).text(), -1);
        if (stringCount < 0) {
            return Optional.empty();
        }

        int stringStart = 3;
        int stringEnd = stringStart + stringCount;
        if (stringEnd > tokens.size()) {
            return Optional.empty();
        }

        List<String> stringTable = new ArrayList<>(stringCount);
        for (int i = stringStart; i < stringEnd; i++) {
            stringTable.add(tokens.get(i).text());
        }

        int payloadStart = stringEnd;
        if (payloadStart + 4 >= tokens.size()) {
            return Optional.empty();
        }

        String moduleBase = resolveRef(tokens.get(payloadStart).text(), stringTable);
        String policy = resolveRef(tokens.get(payloadStart + 1).text(), stringTable);
        String service = resolveRef(tokens.get(payloadStart + 2).text(), stringTable);
        String method = resolveRef(tokens.get(payloadStart + 3).text(), stringTable);
        int paramCount = parseInt(tokens.get(payloadStart + 4).text(), -1);
        if (paramCount < 0) {
            paramCount = 0;
        }

        int paramTypesStart = payloadStart + 5;
        int paramTypesEnd = Math.min(tokens.size(), paramTypesStart + paramCount);
        int paramValuesStart = paramTypesEnd;
        int paramValuesEnd = Math.min(tokens.size(), paramValuesStart + paramCount);
        int availableParamCount = Math.min(paramCount, Math.min(paramTypesEnd - paramTypesStart, paramValuesEnd - paramValuesStart));

        List<ParameterInfo> params = new ArrayList<>(Math.max(availableParamCount, 0));
        for (int i = 0; i < availableParamCount; i++) {
            TokenSpan typeToken = tokens.get(paramTypesStart + i);
            TokenSpan valueToken = tokens.get(paramValuesStart + i);
            int valueRef = parseInt(valueToken.text(), Integer.MIN_VALUE);
            String valueResolved = resolveRef(valueToken.text(), stringTable);
            int mutationTokenIndex = valueToken.index();
            if (valueRef >= 1 && valueRef <= stringTable.size()) {
                mutationTokenIndex = stringStart + (valueRef - 1);
            }
            params.add(new ParameterInfo(
                    i,
                    typeToken.text(),
                    resolveRef(typeToken.text(), stringTable),
                    valueToken.text(),
                    valueResolved,
                    valueToken.index(),
                    mutationTokenIndex
            ));
        }

        return Optional.of(new SemanticRequest(
                protocol,
                flags,
                tokens,
                safe(body).endsWith("|"),
                stringTable,
                moduleBase,
                policy,
                service,
                method,
                paramCount,
                params
        ));
    }

    public static String rebuildBody(SemanticRequest request, int tokenIndex, String replacement) {
        if (tokenIndex < 0 || tokenIndex >= request.tokens().size()) {
            return requestBodyFromTokens(request.tokens(), request.trailingDelimiter());
        }
        List<String> values = new ArrayList<>(request.tokens().size());
        for (TokenSpan token : request.tokens()) {
            values.add(token.text());
        }
        values.set(tokenIndex, sanitizeReplacement(replacement));
        return requestBody(values, request.trailingDelimiter());
    }

    private static String requestBodyFromTokens(List<TokenSpan> tokens, boolean trailingDelimiter) {
        List<String> values = new ArrayList<>(tokens.size());
        for (TokenSpan token : tokens) {
            values.add(token.text());
        }
        return requestBody(values, trailingDelimiter);
    }

    private static String requestBody(List<String> values, boolean trailingDelimiter) {
        String body = String.join("|", values);
        if (trailingDelimiter) {
            return body + "|";
        }
        return body;
    }

    static List<TokenSpan> tokenizePipeWithOffsets(String body) {
        String source = safe(body);
        if (source.isEmpty()) {
            return Collections.emptyList();
        }
        List<TokenSpan> spans = new ArrayList<>();
        int tokenStart = 0;
        int tokenIndex = 0;
        for (int i = 0; i <= source.length(); i++) {
            boolean atDelimiter = i == source.length() || source.charAt(i) == '|';
            if (!atDelimiter) {
                continue;
            }
            // Keep empty interior tokens to preserve index semantics.
            if (!(i == source.length() && source.endsWith("|"))) {
                spans.add(new TokenSpan(tokenIndex++, tokenStart, i, source.substring(tokenStart, i)));
            }
            tokenStart = i + 1;
        }
        return spans;
    }

    private static String resolveRef(String token, List<String> stringTable) {
        int idx = parseInt(token, Integer.MIN_VALUE);
        if (idx >= 1 && idx <= stringTable.size()) {
            return safe(stringTable.get(idx - 1));
        }
        return safe(token);
    }

    private static int parseInt(String token, int fallback) {
        try {
            return Integer.parseInt(safe(token).trim());
        } catch (Exception ex) {
            return fallback;
        }
    }

    private static String sanitizeReplacement(String value) {
        return safe(value).replace("|", "_");
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
