package com.ghidramcpng;

import com.ghidramcpng.tools.ReadTools;
import com.ghidramcpng.tools.ScriptTool;
import com.ghidramcpng.tools.WriteTools;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.jaxrs2.Reader;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

/**
 * CLI utility: generates openapi.json from JAX-RS annotations without a running server.
 * Called by the {@code generateOpenApiSpec} Gradle task; output is consumed by
 * {@code scripts/generate_tools_docs.py} to produce TOOLS.md.
 *
 * Usage: java GenerateSpec [output-path]  (default: build/openapi.json)
 */
public class GenerateSpec {

    public static void main(String[] args) throws Exception {
        String outputPath = args.length > 0 ? args[0] : "build/openapi.json";

        OpenAPI base = new OpenAPI()
                .info(new Info()
                        .title("Ghidra MCP API")
                        .version("0.1.0")
                        .description("Ghidra binary-analysis tools exposed as MCP tools for AI agents."));

        OpenAPI spec = new Reader(base)
                .read(Set.of(ReadTools.class, WriteTools.class, ScriptTool.class));

        String json = Json.mapper()
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(spec);

        Path out = Path.of(outputPath);
        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }
        Files.writeString(out, json, StandardCharsets.UTF_8);
        System.out.println("Spec written to " + outputPath + " (" + json.length() + " bytes)");
    }
}
