import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class GwtDetector {
    private static final Pattern CACHE_JS_PATTERN = Pattern.compile("([A-Za-z0-9_./\\-]+\\.cache\\.js)", Pattern.CASE_INSENSITIVE);
    private static final Pattern NOCACHE_JS_PATTERN = Pattern.compile("([A-Za-z0-9_./\\-]+\\.nocache\\.js)", Pattern.CASE_INSENSITIVE);
    private static final Pattern GWT_RPC_POLICY_PATTERN = Pattern.compile("([A-Za-z0-9_./\\-]+\\.gwt\\.rpc)", Pattern.CASE_INSENSITIVE);

    private GwtDetector() {
    }

    public static boolean looksLikeGwtRpcRequest(HttpRequest request) {
        if (request == null) {
            return false;
        }

        String body;
        try {
            body = request.bodyToString();
        } catch (Exception ex) {
            body = "";
        }

        List<String> headers = new ArrayList<>();
        try {
            for (HttpHeader h : request.headers()) {
                headers.add(h.name() + ": " + h.value());
            }
        } catch (Exception ex) {
            // Burp may provide partially initialized editor messages where headers() can throw.
            // Fallback to body-only detection in that case.
        }
        return looksLikeGwtRpcPayload(body, headers);
    }

    public static boolean looksLikeGwtRpcPayload(String body, List<String> headerLines) {
        String payload = safe(body).trim();
        if (payload.matches("^\\d+\\|\\d+\\|.*")) {
            return true;
        }

        for (String line : headerLines) {
            String lower = safe(line).toLowerCase(Locale.ROOT);
            if (lower.startsWith("x-gwt-permutation:")) {
                return true;
            }
            if (lower.startsWith("x-gwt-module-base:")) {
                return true;
            }
            if (lower.startsWith("content-type:") && lower.contains("text/x-gwt-rpc")) {
                return true;
            }
        }
        return false;
    }

    public static boolean isPotentialGwtPath(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.endsWith(".cache.js") || lower.endsWith(".nocache.js") || lower.endsWith(".gwt.rpc");
    }

    public static String classifyArtifact(String path) {
        String lower = safe(path).toLowerCase(Locale.ROOT);
        if (lower.endsWith(".cache.js")) {
            return "GWT Cache JS";
        }
        if (lower.endsWith(".nocache.js")) {
            return "GWT NoCache JS";
        }
        if (lower.endsWith(".gwt.rpc")) {
            return "GWT RPC Policy";
        }
        return "GWT Artifact";
    }

    public static List<String> extractArtifactPaths(String content) {
        if (content == null || content.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> out = new ArrayList<>();
        addMatches(content, CACHE_JS_PATTERN, out);
        addMatches(content, NOCACHE_JS_PATTERN, out);
        addMatches(content, GWT_RPC_POLICY_PATTERN, out);
        return out;
    }

    public static String resolvePath(String baseUrl, String discoveredPath) {
        try {
            URI base = URI.create(baseUrl);
            URI resolved = base.resolve(discoveredPath);
            return resolved.toString();
        } catch (Exception ex) {
            return discoveredPath;
        }
    }

    public static String hostFromUrl(String url) {
        try {
            String host = URI.create(url).getHost();
            return host == null ? "unknown-host" : host;
        } catch (Exception ignored) {
            return "unknown-host";
        }
    }

    private static void addMatches(String input, Pattern pattern, List<String> out) {
        Matcher matcher = pattern.matcher(input);
        while (matcher.find()) {
            out.add(matcher.group(1));
        }
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
