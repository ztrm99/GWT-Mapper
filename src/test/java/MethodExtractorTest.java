import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MethodExtractorTest {

    // --- extractCacheMethodsLikeGwtMap ---

    @Test
    void extractCacheMethodsFindsInterfaceAndMethodFromNewPattern() {
        // Simulates: new SomeClass(x, y, 'doStuff') followed by invoke('com.example.Service', 3)
        String code = "var a=1;\n" +
                "new SomeClass(x, y, 'doStuff');\n" +
                "invoke(x, 'com.example.Service', 3);\n";
        Set<String> methods = MethodExtractor.extractCacheMethodsLikeGwtMap(code);
        assertTrue(methods.contains("com.example.Service::doStuff"));
    }

    @Test
    void extractCacheMethodsFindsBareMethodNameWhenNoInterface() {
        String code = "new SomeClass(x, y, 'myMethod');\n" +
                "somethingElse();\n";
        Set<String> methods = MethodExtractor.extractCacheMethodsLikeGwtMap(code);
        assertTrue(methods.contains("myMethod"));
    }

    @Test
    void extractCacheMethodsReturnsEmptyForEmptyInput() {
        assertTrue(MethodExtractor.extractCacheMethodsLikeGwtMap("").isEmpty());
    }

    @Test
    void extractCacheMethodsReturnsEmptyForNullInput() {
        assertTrue(MethodExtractor.extractCacheMethodsLikeGwtMap(null).isEmpty());
    }

    @Test
    void extractCacheMethodsResolvesObfuscatedVarToInterface() {
        // When the invoke function is detected and used with a variable that maps to an interface,
        // the variable should resolve through stringVars.
        // detectRpcInvokeFunction needs literal 'com.xxx' calls to identify the invoke function.
        String code = "myFn(x, 'com.example.SvcA', 3);\n" +
                "myFn(y, 'com.example.SvcB', 2);\n" +
                "ifaceVar='com.example.Service';\n" +
                "new X(p, q, 'save');\n" +
                "myFn(z, ifaceVar, 5);\n";
        Set<String> methods = MethodExtractor.extractCacheMethodsLikeGwtMap(code);
        assertTrue(methods.contains("com.example.Service::save"),
                "Expected obfuscated var to resolve to interface. Got: " + methods);
    }

    @Test
    void extractCacheMethodsRespectsMethodCap() {
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < 210; i++) {
            code.append("new SomeClass(x, y, 'method").append(i).append("');\n");
        }
        Set<String> methods = MethodExtractor.extractCacheMethodsLikeGwtMap(code.toString());
        assertTrue(methods.size() <= 200, "Should cap at 200 methods, got " + methods.size());
    }

    // --- extractPermutationsFromNoCache ---

    @Test
    void extractPermutationsFindsCleanModeHashes() {
        String code = "unflattenKeylistIntoAnswers(['gecko1_8'],'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6')\n" +
                "unflattenKeylistIntoAnswers(['safari'],'F6E5D4C3B2A1F6E5D4C3B2A1F6E5D4C3')";
        Set<String> perms = MethodExtractor.extractPermutationsFromNoCache(code);
        assertEquals(2, perms.size());
        assertTrue(perms.contains("A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"));
        assertTrue(perms.contains("F6E5D4C3B2A1F6E5D4C3B2A1F6E5D4C3"));
    }

    @Test
    void extractPermutationsFindsObfuscatedModeHashes() {
        String code = "selectingPermutation\nvar x='A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6';";
        Set<String> perms = MethodExtractor.extractPermutationsFromNoCache(code);
        assertTrue(perms.contains("A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"));
    }

    @Test
    void extractPermutationsReturnsEmptyForNonNoCacheContent() {
        assertTrue(MethodExtractor.extractPermutationsFromNoCache("var x = 42;").isEmpty());
    }

    @Test
    void extractPermutationsRespectsPermutationCap() {
        StringBuilder code = new StringBuilder("selectingPermutation\n");
        for (int i = 0; i < 25; i++) {
            code.append(String.format("A%031d", i)).append("\n");
        }
        Set<String> perms = MethodExtractor.extractPermutationsFromNoCache(code.toString());
        assertTrue(perms.size() <= 20, "Should cap at 20 permutations, got " + perms.size());
    }

    // --- extractGwtVersion ---

    @Test
    void extractGwtVersionFindsVersionFromGwtVersionProperty() {
        assertEquals("2.8.2", MethodExtractor.extractGwtVersion("gwtVersion='2.8.2'"));
    }

    @Test
    void extractGwtVersionFindsVersionFromGoogleWebToolkit() {
        assertEquals("2.10.0", MethodExtractor.extractGwtVersion("Google Web Toolkit 2.10.0"));
    }

    @Test
    void extractGwtVersionReturnsEmptyWhenNoVersion() {
        assertEquals("", MethodExtractor.extractGwtVersion("just some random javascript code"));
    }

    // --- extractMethodHints ---

    @Test
    void extractMethodHintsFindsClassMethodPatterns() {
        String body = "com.example.Service::doStuff(param)";
        Set<String> hints = MethodExtractor.extractMethodHints(body);
        assertTrue(hints.contains("com.example.Service::doStuff"));
    }

    @Test
    void extractMethodHintsFindsDotMethodPatterns() {
        String body = "obj.processRequest(data)";
        Set<String> hints = MethodExtractor.extractMethodHints(body);
        assertTrue(hints.contains("processRequest"));
    }

    @Test
    void extractMethodHintsRespectsMethodCap() {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 25; i++) {
            body.append("com.example.Svc").append(i).append("::method").append(i).append("()\n");
        }
        Set<String> hints = MethodExtractor.extractMethodHints(body.toString());
        assertTrue(hints.size() <= 20, "Should cap at 20 methods, got " + hints.size());
    }

    // --- detectRpcInvokeFunction ---

    @Test
    void detectRpcInvokeFunctionIdentifiesJUbHUbMarkers() {
        String[] lines = {
                "function myRpcFn(a,b,c){",
                "  var x = JUb(a);",
                "  var y = JUb(b);",
                "  HUb(c);",
                "}"
        };
        assertEquals("myRpcFn", MethodExtractor.detectRpcInvokeFunction(lines));
    }

    @Test
    void detectRpcInvokeFunctionFallsBackToFrequencyBasedDetection() {
        String[] lines = {
                "doInvoke(x, 'com.example.Svc1', 3)",
                "doInvoke(y, 'com.example.Svc2', 5)",
                "other(z, 'com.other.Thing', 1)"
        };
        assertEquals("doInvoke", MethodExtractor.detectRpcInvokeFunction(lines));
    }

    @Test
    void detectRpcInvokeFunctionReturnsEmptyForNoMatch() {
        String[] lines = {"var a = 1;", "var b = 2;"};
        assertEquals("", MethodExtractor.detectRpcInvokeFunction(lines));
    }

    // --- normalizeCacheCodeForHeuristics ---

    @Test
    void normalizeCacheCodeSkipsNormalizationForFunctionPrefix() {
        String input = "function foo(){return 1;}";
        assertEquals(input, MethodExtractor.normalizeCacheCodeForHeuristics(input));
    }

    @Test
    void normalizeCacheCodeExpandsBracesAndSemicolons() {
        String input = "a=1;b={c:2}";
        String normalized = MethodExtractor.normalizeCacheCodeForHeuristics(input);
        assertTrue(normalized.contains("{\n"), "Should expand { to {\\n");
        assertTrue(normalized.contains(";\n"), "Should expand ; to ;\\n");
    }
}
