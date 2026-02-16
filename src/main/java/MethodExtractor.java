import java.util.LinkedHashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Stateless utility for extracting GWT service methods, version strings,
 * and permutation hashes from compiled GWT JavaScript artifacts.
 */
public final class MethodExtractor {

    private static final Pattern ASSIGN_PAT = Pattern.compile("([A-Za-z0-9_$]+)=['\"]([^'\"]*)['\"]");
    private static final Pattern NEW_LIT_PAT = Pattern.compile("new\\s+[A-Za-z0-9_.$]+\\([^;]*,\\s*([A-Za-z0-9_$]+)\\s*,\\s*'([^']+)'\\s*\\)");
    private static final Pattern NEW_VAR_PAT = Pattern.compile("new\\s+[A-Za-z0-9_.$]+\\([^;]*,\\s*([A-Za-z0-9_$]+)\\s*,\\s*([A-Za-z0-9_$]+)\\s*\\)");
    private static final Pattern INVOKE_LITERAL_IFACE = Pattern.compile("\\b([A-Za-z0-9_$]+)\\([^;]*'((?:com|org|net)\\.[^']+)'\\s*,\\s*(\\d+)\\s*\\)");
    private static final Pattern METHOD_NAME_PAT = Pattern.compile("^[A-Za-z0-9_$]+$");
    private static final Pattern FN_PAT = Pattern.compile("^function\\s+([A-Za-z0-9_$]+)\\(a,b,c\\)\\{");
    private static final Pattern LITERAL_INVOKE_PAT = Pattern.compile("\\b([A-Za-z0-9_$]+)\\([^;]*'com\\.[^']+'\\s*,\\s*\\d+\\s*\\)");
    private static final Pattern RPC_STYLE_PAT = Pattern.compile("([A-Za-z0-9_$.]+)::([A-Za-z0-9_]+)\\(");
    private static final Pattern JS_CALLS_PAT = Pattern.compile("\\.([A-Za-z_][A-Za-z0-9_]{2,})\\(");
    private static final Pattern IFACE_METHOD_LITERAL_PAT = Pattern.compile("['\"]((?:com|org|net)\\.[A-Za-z0-9_$.]+)['\"]\\s*,\\s*['\"]([A-Za-z_][A-Za-z0-9_$]{1,})['\"]");
    private static final Pattern METHOD_IFACE_LITERAL_PAT = Pattern.compile("['\"]([A-Za-z_][A-Za-z0-9_$]{1,})['\"]\\s*,\\s*['\"]((?:com|org|net)\\.[A-Za-z0-9_$.]+)['\"]");
    private static final Pattern SERVICE_METHOD_PAIR_PAT = Pattern.compile("((?:com|org|net)\\.[A-Za-z0-9_$.]+)[^\\n]{0,140}::([A-Za-z0-9_]+)");
    private static final Pattern GWT_VERSION_1 = Pattern.compile("gwtVersion\\s*[:=]\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern GWT_VERSION_2 = Pattern.compile("GWT_VERSION\\s*[:=]\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern GWT_VERSION_3 = Pattern.compile("Google Web Toolkit\\s*([0-9]+(?:\\.[0-9]+)+)", Pattern.CASE_INSENSITIVE);
    private static final List<Pattern> GWT_VERSION_PATTERNS = List.of(GWT_VERSION_1, GWT_VERSION_2, GWT_VERSION_3);
    private static final Pattern CLEAN_PERM_PAT = Pattern.compile("unflattenKeylistIntoAnswers\\([^\\n]*'([A-Z0-9]{32})'\\)");
    private static final Pattern OBF_PERM_PAT = Pattern.compile("([A-Z0-9]{32})");

    private MethodExtractor() {}

    /**
     * Heuristics adapted from reference/gwtmap.py and reference/gwtmap_ng.py.
     * Parses compiled .cache.js to recover service interface/method names.
     */
    public static Set<String> extractCacheMethodsLikeGwtMap(String body) {
        Set<String> methods = new LinkedHashSet<>();
        String source = safe(body);
        if (source.isEmpty()) {
            return methods;
        }

        String normalized = normalizeCacheCodeForHeuristics(source);
        String[] lines = normalized.split("\\n");

        // obfuscatedVar='literal' and obfuscatedVar="literal"
        var stringVars = new HashMap<String, String>();
        Matcher assign = ASSIGN_PAT.matcher(normalized);
        while (assign.find()) {
            stringVars.put(assign.group(1), assign.group(2));
        }

        String invokeFn = detectRpcInvokeFunction(lines);

        Pattern invokeByFunction = null;
        if (!invokeFn.isEmpty()) {
            invokeByFunction = Pattern.compile("\\b" + Pattern.quote(invokeFn) + "\\([^;]*,\\s*([A-Za-z0-9_$]+|'[^']+')\\s*,\\s*(\\d+)\\s*\\)");
        }

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String methodName = null;

            Matcher m1 = NEW_LIT_PAT.matcher(line);
            if (m1.find()) {
                methodName = m1.group(2);
            } else {
                Matcher m2 = NEW_VAR_PAT.matcher(line);
                if (m2.find()) {
                    methodName = stringVars.getOrDefault(m2.group(2), "");
                }
            }
            if (methodName == null || methodName.isEmpty() || !METHOD_NAME_PAT.matcher(methodName).matches()) {
                continue;
            }

            String iface = "";
            int forwardTo = Math.min(lines.length, i + 30);
            for (int j = i; j < forwardTo; j++) {
                if (invokeByFunction != null) {
                    Matcher byFunc = invokeByFunction.matcher(lines[j]);
                    if (byFunc.find()) {
                        iface = byFunc.group(1).replace("'", "");
                        break;
                    }
                }
                Matcher inv = INVOKE_LITERAL_IFACE.matcher(lines[j]);
                if (inv.find()) {
                    iface = inv.group(2);
                    break;
                }
            }
            if (iface.isEmpty()) {
                int backwardFrom = Math.max(0, i - 10);
                for (int j = backwardFrom; j < i; j++) {
                    if (invokeByFunction != null) {
                        Matcher byFunc = invokeByFunction.matcher(lines[j]);
                        if (byFunc.find()) {
                            iface = byFunc.group(1).replace("'", "");
                            break;
                        }
                    }
                    Matcher inv = INVOKE_LITERAL_IFACE.matcher(lines[j]);
                    if (inv.find()) {
                        iface = inv.group(2);
                        break;
                    }
                }
            }
            iface = stringVars.getOrDefault(iface, iface);

            if (iface.startsWith("com.") || iface.startsWith("org.") || iface.startsWith("net.")) {
                methods.add(iface + "::" + methodName);
            } else {
                methods.add(methodName);
            }
            if (methods.size() >= 200) {
                break;
            }
        }

        return methods;
    }

    static String normalizeCacheCodeForHeuristics(String source) {
        if (source.startsWith("function")) {
            return source;
        }
        return source
                .replace("{", "{\n")
                .replace("}", "\n}\n")
                .replace(";", ";\n");
    }

    static String detectRpcInvokeFunction(String[] codeLines) {
        for (int i = 0; i < codeLines.length; i++) {
            Matcher m = FN_PAT.matcher(codeLines[i].trim());
            if (!m.find()) {
                continue;
            }
            String name = m.group(1);
            int jUb = 0;
            int hUb = 0;
            for (int j = i + 1; j < Math.min(i + 25, codeLines.length); j++) {
                if (codeLines[j].contains("JUb(")) {
                    jUb++;
                }
                if (codeLines[j].contains("HUb(")) {
                    hUb++;
                }
                if (codeLines[j].trim().equals("}")) {
                    break;
                }
            }
            if (jUb >= 2 && hUb >= 1) {
                return name;
            }
        }

        var candidates = new HashMap<String, Integer>();
        for (String line : codeLines) {
            Matcher matcher = LITERAL_INVOKE_PAT.matcher(line);
            if (matcher.find()) {
                String candidate = matcher.group(1);
                candidates.put(candidate, candidates.getOrDefault(candidate, 0) + 1);
            }
        }

        String best = "";
        int bestScore = 0;
        for (var entry : candidates.entrySet()) {
            if (entry.getValue() > bestScore) {
                best = entry.getKey();
                bestScore = entry.getValue();
            }
        }
        return best;
    }

    public static Set<String> extractMethodHints(String body) {
        Set<String> methods = new LinkedHashSet<>();
        String source = safe(body);
        if (source.isEmpty()) {
            return methods;
        }

        Matcher rpcStyle = RPC_STYLE_PAT.matcher(source);
        while (rpcStyle.find() && methods.size() < 20) {
            addMethod(methods, rpcStyle.group(1), rpcStyle.group(2));
        }
        Matcher quotedIfaceMethod = IFACE_METHOD_LITERAL_PAT.matcher(source);
        while (quotedIfaceMethod.find() && methods.size() < 20) {
            addMethod(methods, quotedIfaceMethod.group(1), quotedIfaceMethod.group(2));
        }
        Matcher quotedMethodIface = METHOD_IFACE_LITERAL_PAT.matcher(source);
        while (quotedMethodIface.find() && methods.size() < 20) {
            addMethod(methods, quotedMethodIface.group(2), quotedMethodIface.group(1));
        }
        Matcher serviceMethodPairs = SERVICE_METHOD_PAIR_PAT.matcher(source);
        while (serviceMethodPairs.find() && methods.size() < 20) {
            addMethod(methods, serviceMethodPairs.group(1), serviceMethodPairs.group(2));
        }
        Matcher jsCalls = JS_CALLS_PAT.matcher(source);
        while (jsCalls.find() && methods.size() < 20) {
            String method = jsCalls.group(1);
            if (isLikelyMethodName(method)) {
                methods.add(method);
            }
        }
        return methods;
    }

    public static String extractGwtVersion(String body) {
        String source = safe(body);
        if (source.isEmpty()) {
            return "";
        }
        for (Pattern p : GWT_VERSION_PATTERNS) {
            Matcher m = p.matcher(source);
            if (m.find()) {
                return m.group(1);
            }
        }
        return "";
    }

    public static Set<String> extractPermutationsFromNoCache(String code) {
        Set<String> permutations = new LinkedHashSet<>();
        String source = safe(code);
        // gwtmap clean-mode style: unflattenKeylistIntoAnswers(...,'<32hex>')
        Matcher clean = CLEAN_PERM_PAT.matcher(source);
        while (clean.find()) {
            permutations.add(clean.group(1));
            if (permutations.size() >= 20) {
                return permutations;
            }
        }
        // gwtmap obfuscated style: selectingPermutation marker and embedded IDs
        if (source.contains("selectingPermutation")) {
            Matcher obf = OBF_PERM_PAT.matcher(source);
            while (obf.find()) {
                permutations.add(obf.group(1));
                if (permutations.size() >= 20) {
                    break;
                }
            }
        }
        return permutations;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static void addMethod(Set<String> out, String iface, String method) {
        String normalizedIface = safe(iface).trim();
        String normalizedMethod = safe(method).trim();
        if (!isLikelyMethodName(normalizedMethod)) {
            return;
        }
        if (normalizedIface.startsWith("com.") || normalizedIface.startsWith("org.") || normalizedIface.startsWith("net.")) {
            out.add(normalizedIface + "::" + normalizedMethod);
        } else {
            out.add(normalizedMethod);
        }
    }

    private static boolean isLikelyMethodName(String method) {
        if (method.isEmpty() || method.length() < 2) {
            return false;
        }
        String lower = method.toLowerCase();
        return !lower.equals("call")
                && !lower.equals("apply")
                && !lower.equals("bind")
                && !lower.equals("push")
                && !lower.equals("pop")
                && !lower.equals("slice")
                && !lower.equals("splice");
    }
}
