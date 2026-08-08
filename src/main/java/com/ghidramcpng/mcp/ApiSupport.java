package com.ghidramcpng.mcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Collection;
import java.util.List;

public final class ApiSupport {

    public static final Gson GSON = HttpApiServer.GsonProvider.GSON;

    private ApiSupport() {}

    public static Response ok(JsonElement result) {
        JsonObject envelope = new JsonObject();
        envelope.addProperty("ok", true);
        envelope.add("result", result);
        return Response.ok(GSON.toJson(envelope), MediaType.APPLICATION_JSON).build();
    }

    public static Response error(Response.Status status, String message) {
        return error(status.getStatusCode(), message, null);
    }

    /**
     * @param errorId id of the server-log entry holding the full stack trace, or null when the
     *                message is the whole story (a rejected argument, say) and nothing was logged
     */
    public static Response error(int status, String message, String errorId) {
        JsonObject envelope = new JsonObject();
        envelope.addProperty("ok", false);
        envelope.addProperty("error", message);
        if (errorId != null) {
            envelope.addProperty("error_id", errorId);
        }
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON)
                .entity(GSON.toJson(envelope))
                .build();
    }

    /**
     * Returns the candidate closest to {@code provided}, or null if none is close enough to be
     * worth suggesting. Shared by every "did you mean" message so a near-miss reads the same
     * way whether it is a query parameter, a tool name, or anything else.
     */
    public static String suggestClosest(String provided, Collection<String> candidates) {
        String best = null;
        int bestDistance = Integer.MAX_VALUE;
        for (String candidate : candidates) {
            int distance = levenshtein(provided.toLowerCase(), candidate.toLowerCase());
            if (distance < bestDistance) {
                bestDistance = distance;
                best = candidate;
            }
        }
        // Only suggest when the names are genuinely similar (or one contains the other),
        // so we don't emit a misleading hint for a wholly unrelated name.
        int threshold = Math.max(2, provided.length() / 2);
        boolean substring = best != null
                && (best.toLowerCase().contains(provided.toLowerCase())
                    || provided.toLowerCase().contains(best.toLowerCase()));
        return (best != null && (bestDistance <= threshold || substring)) ? best : null;
    }

    private static int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] curr = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            curr[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = curr;
            curr = tmp;
        }
        return prev[b.length()];
    }

    public static int intOrDefault(Integer value, int defaultValue) {
        return value != null ? value : defaultValue;
    }

    public static boolean boolOrDefault(Boolean value, boolean defaultValue) {
        return value != null ? value : defaultValue;
    }

    public static void add(JsonObject args, String name, String value) {
        if (value != null) {
            args.addProperty(name, value);
        }
    }

    public static void add(JsonObject args, String name, Integer value) {
        if (value != null) {
            args.addProperty(name, value);
        }
    }

    public static void add(JsonObject args, String name, Boolean value) {
        if (value != null) {
            args.addProperty(name, value);
        }
    }

    public static void addArray(JsonObject args, String name, List<String> values) {
        if (values == null) {
            return;
        }
        JsonArray array = new JsonArray();
        for (String value : values) {
            array.add(value);
        }
        args.add(name, array);
    }
}