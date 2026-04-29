package com.ghidramcpng.mcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

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
        JsonObject envelope = new JsonObject();
        envelope.addProperty("ok", false);
        envelope.addProperty("error", message);
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON)
                .entity(GSON.toJson(envelope))
                .build();
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