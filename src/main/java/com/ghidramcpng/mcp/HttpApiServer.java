package com.ghidramcpng.mcp;

import ghidra.program.model.address.Address;
import com.ghidramcpng.rules.NamingRuleViolation;
import com.ghidramcpng.tools.ReadTools;
import com.ghidramcpng.tools.ScriptTool;
import com.ghidramcpng.tools.WriteTools;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.jaxrs2.integration.JaxrsOpenApiContextBuilder;
import io.swagger.v3.oas.integration.OpenApiContextLocator;
import io.swagger.v3.oas.integration.SwaggerConfiguration;
import io.swagger.v3.oas.integration.api.OpenApiContext;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.ext.ContextResolver;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.util.Set;

/**
 * HTTP API server that exposes annotated JAX-RS tool endpoints and generated OpenAPI schema.
 */
public class HttpApiServer {

    private static final String VERSION = "0.1.0";
    private static final String OPENAPI_CONTEXT_ID = "ghidra-mcp-ng";

    private final int port;
    private final ReadTools readTools;
    private final WriteTools writeTools;
    private final ScriptTool scriptTool;
    private final PrintStream log;
    private com.sun.net.httpserver.HttpServer server;

    public HttpApiServer(int port, ReadTools readTools, WriteTools writeTools, ScriptTool scriptTool) {
        this(port, readTools, writeTools, scriptTool, System.err);
    }

    public HttpApiServer(int port, ReadTools readTools, WriteTools writeTools,
            ScriptTool scriptTool, PrintStream log) {
        this.port = port;
        this.readTools = readTools;
        this.writeTools = writeTools;
        this.scriptTool = scriptTool;
        this.log = log;
    }

    public void start() throws IOException {
        final MetaResource metaResource = new MetaResource();
        final ReadTools rt = readTools;
        final WriteTools wt = writeTools;
        final ScriptTool st = scriptTool;

        ResourceConfig config = new ResourceConfig()
                .register(ApiExceptionMapper.class)
                .register(GsonProvider.class)
                .register(MetaResource.class)
                .register(ReadTools.class)
                .register(WriteTools.class)
                .register(ScriptTool.class)
                .register(new AbstractBinder() {
                    @Override
                    protected void configure() {
                        bind(metaResource).to(MetaResource.class);
                        bind(rt).to(ReadTools.class);
                        bind(wt).to(WriteTools.class);
                        bind(st).to(ScriptTool.class);
                    }
                });

        SwaggerConfiguration openApiConfig = new SwaggerConfiguration()
                .openAPI(new OpenAPI().info(new Info()
                        .title("ghidra-mcp-ng")
                        .version(VERSION)
                        .description("Annotation-driven HTTP API for Ghidra MCP tools")))
                .prettyPrint(true)
                .resourceClasses(Set.of(
                        ReadTools.class.getName(),
                        WriteTools.class.getName(),
                        ScriptTool.class.getName()));

        try {
            new JaxrsOpenApiContextBuilder()
                    .ctxId(OPENAPI_CONTEXT_ID)
                    .openApiConfiguration(openApiConfig)
                    .buildContext(true);
        } catch (Exception e) {
            throw new IOException("Failed to initialize OpenAPI context", e);
        }

        server = JdkHttpServerFactory.createHttpServer(
                UriBuilder.fromUri(URI.create("http://127.0.0.1:" + port + "/")).build(),
                config,
                false);
        server.start();
        log.printf("[ghidra-mcp-ng] HTTP API listening on http://127.0.0.1:%d%n", port);
    }

    public void stop() {
        if (server != null) {
            server.stop(1);
        }
    }

    @Path("")
    public static class MetaResource {

        @GET
        @Path("health")
        @Produces(MediaType.APPLICATION_JSON)
        public Response health() {
            var body = new com.google.gson.JsonObject();
            body.addProperty("status", "ok");
            body.addProperty("version", VERSION);
            body.addProperty("tools", ReadTools.TOOL_COUNT + WriteTools.TOOL_COUNT + ScriptTool.TOOL_COUNT);
            return Response.ok(ApiSupport.GSON.toJson(body), MediaType.APPLICATION_JSON).build();
        }

        @GET
        @Path("schema")
        @Produces(MediaType.APPLICATION_JSON)
        public Response schema() {
            return openApiResponse();
        }

        @GET
        @Path("openapi.json")
        @Produces(MediaType.APPLICATION_JSON)
        public Response openApiJson() {
            return openApiResponse();
        }

        private Response openApiResponse() {
            try {
                OpenApiContext context = OpenApiContextLocator.getInstance().getOpenApiContext(OPENAPI_CONTEXT_ID);
                if (context == null) {
                    return ApiSupport.error(Response.Status.INTERNAL_SERVER_ERROR,
                            "OpenAPI context is not initialized");
                }
                OpenAPI openApi = context.read();
                return Response.ok(Json.pretty(openApi), MediaType.APPLICATION_JSON).build();
            } catch (Exception e) {
                return ApiSupport.error(Response.Status.INTERNAL_SERVER_ERROR,
                        "Failed to build OpenAPI schema: " + e.getMessage());
            }
        }
    }

    @Provider
    @Produces(MediaType.APPLICATION_JSON)
    public static class GsonProvider implements ContextResolver<Gson> {

        static final Gson GSON = new GsonBuilder()
                .disableHtmlEscaping()
                .registerTypeAdapter(Address.class,
                        (JsonSerializer<Address>) (src, typeOfSrc, ctx) -> new JsonPrimitive("0x" + src.toString()))
                .create();

        @Override
        public Gson getContext(Class<?> type) {
            return GSON;
        }
    }

    @Provider
    public static class ApiExceptionMapper implements ExceptionMapper<Throwable> {

        @Override
        public Response toResponse(Throwable exception) {
            if (exception instanceof NamingRuleViolation || exception instanceof IllegalArgumentException) {
                return ApiSupport.error(Response.Status.BAD_REQUEST, exception.getMessage());
            }
            return ApiSupport.error(Response.Status.INTERNAL_SERVER_ERROR,
                    "Internal error: " + exception.getMessage());
        }
    }
}
