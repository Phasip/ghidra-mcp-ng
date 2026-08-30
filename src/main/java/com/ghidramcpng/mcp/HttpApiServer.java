package com.ghidramcpng.mcp;

import ghidra.program.model.address.Address;
import com.ghidramcpng.rules.NamingRuleViolation;
import com.ghidramcpng.tools.ReadTools;
import com.ghidramcpng.tools.ScriptTool;
import com.ghidramcpng.tools.ToolHelpers;
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
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ContextResolver;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.jdkhttp.JdkHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * HTTP API server that exposes annotated JAX-RS tool endpoints and generated OpenAPI schema.
 */
public class HttpApiServer {

    private static final String VERSION = "0.1.0";
    private static final String OPENAPI_CONTEXT_ID = "ghidra-mcp-ng";

    /**
     * Identifies this server process. The OpenAPI schema is generated from the code that is
     * running, so a client that caches it needs to know when that code was replaced — a rebuild
     * and restart under a long-lived bridge is exactly how a cached schema starts advertising
     * fields the live server rejects. This changes on every start, and nothing else does.
     */
    private static final String STARTED_AT = java.time.Instant.now().toString();

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
                .register(UnknownQueryParamFilter.class)
                .register(UnknownBodyFieldFilter.class)
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
            // Cache token for the generated schema: a client re-fetches /openapi.json whenever
            // this changes. See bridge.py's get_spec.
            body.addProperty("started_at", STARTED_AT);
            body.addProperty("tools", ReadTools.TOOL_COUNT + WriteTools.TOOL_COUNT + ScriptTool.TOOL_COUNT);
            // So whoever holds an error_id can find the stack trace it refers to without
            // having to ask the operator where the server writes.
            body.addProperty("log_file",
                    ServerLog.getFile() != null ? ServerLog.getFile().toString() : null);
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

    /**
     * Rejects any query parameter that the matched endpoint does not declare, instead of
     * silently ignoring it (the JAX-RS default). Silently dropping an unknown parameter is a
     * foot-gun for callers: e.g. calling {@code read_data?count=112} (the real parameter is
     * {@code item_count}) would otherwise fall back to defaults and look like the tool ignored
     * the request. A clear 400 that names the valid parameters — and suggests the closest match —
     * lets an AI agent self-correct on the first try.
     */
    @Provider
    public static class UnknownQueryParamFilter implements ContainerRequestFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext) {
            Method method = resourceInfo.getResourceMethod();
            if (method == null) {
                return;
            }

            Set<String> allowed = new TreeSet<>();
            for (Parameter parameter : method.getParameters()) {
                QueryParam queryParam = parameter.getAnnotation(QueryParam.class);
                if (queryParam != null) {
                    allowed.add(queryParam.value());
                }
            }

            List<String> unknown = new ArrayList<>();
            for (String provided : requestContext.getUriInfo().getQueryParameters().keySet()) {
                if (!allowed.contains(provided)) {
                    unknown.add(provided);
                }
            }
            if (unknown.isEmpty()) {
                return;
            }

            String endpoint = requestContext.getMethod() + " " + requestContext.getUriInfo().getPath();
            requestContext.abortWith(ApiSupport.error(Response.Status.BAD_REQUEST,
                    ApiSupport.unknownNamesMessage("query parameter", unknown, allowed,
                            "endpoint '" + endpoint + "'")));
        }
    }

    /**
     * The same rejection for a POST body: a field the tool does not declare is refused rather
     * than dropped. This is the more dangerous half of the two, because most body fields are
     * optional — {@code set_comment} sent {@code comment_type} would have written the default
     * PRE comment and returned success, and {@code import_binary} sent {@code base_addr} would
     * have loaded at the wrong base and reported it as done.
     *
     * <p>The accepted vocabulary is the request record's own components, so it is the published
     * schema by construction and cannot drift from it.
     */
    @Provider
    public static class UnknownBodyFieldFilter implements ContainerRequestFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext) throws IOException {
            Method method = resourceInfo.getResourceMethod();
            if (method == null || !method.isAnnotationPresent(jakarta.ws.rs.POST.class)
                    || !requestContext.hasEntity()) {
                return;
            }
            Set<String> allowed = ToolHelpers.argumentNames(method);
            if (allowed == null) {
                return;
            }

            // The body is consumed here, so hand the tool an identical copy to read.
            byte[] body = requestContext.getEntityStream().readAllBytes();
            requestContext.setEntityStream(new java.io.ByteArrayInputStream(body));

            com.google.gson.JsonObject parsed;
            try {
                com.google.gson.JsonElement element = com.google.gson.JsonParser.parseString(
                        new String(body, java.nio.charset.StandardCharsets.UTF_8));
                if (!element.isJsonObject()) {
                    return;   // not an object: the tool's own required-parameter checks report it
                }
                parsed = element.getAsJsonObject();
            } catch (RuntimeException e) {
                return;       // malformed JSON: GsonProvider reports it
            }

            List<String> unknown = new ArrayList<>();
            for (String provided : parsed.keySet()) {
                if (!allowed.contains(provided)) {
                    unknown.add(provided);
                }
            }
            if (unknown.isEmpty()) {
                return;
            }

            jakarta.ws.rs.Path path = method.getAnnotation(jakarta.ws.rs.Path.class);
            String tool = path != null ? path.value().replaceAll("^/+", "") : method.getName();
            requestContext.abortWith(ApiSupport.error(Response.Status.BAD_REQUEST,
                    ApiSupport.unknownNamesMessage("field", unknown, allowed, "tool '" + tool + "'")));
        }
    }

    /**
     * Turns every escaping exception into the standard {@code {"ok":false,"error":...}} envelope.
     *
     * <p>Three kinds, three treatments. A rejected argument is the caller's to fix, so it becomes
     * a 400 carrying only the message. A JAX-RS routing failure keeps its own status — a call to a
     * tool that does not exist must read as 404, not as an internal error. Anything else is a
     * server bug: the full stack goes to {@link ServerLog} and the response quotes the resulting
     * {@code error_id} so a report can name the exact entry.
     */
    @Provider
    public static class ApiExceptionMapper implements ExceptionMapper<Throwable> {

        @Context
        private UriInfo uriInfo;

        @Context
        private jakarta.ws.rs.core.Request request;

        @Override
        public Response toResponse(Throwable exception) {
            if (exception instanceof NamingRuleViolation || exception instanceof IllegalArgumentException) {
                return ApiSupport.error(Response.Status.BAD_REQUEST, exception.getMessage());
            }
            if (exception instanceof NotFoundException) {
                return ApiSupport.error(Response.Status.NOT_FOUND.getStatusCode(), unknownEndpointMessage(), null);
            }
            if (exception instanceof WebApplicationException webApp) {
                // Routing and protocol failures (405, 415, …) already carry the right status and
                // a message that says what is wrong with the request itself.
                return ApiSupport.error(webApp.getResponse().getStatus(), webApp.getMessage(), null);
            }

            String errorId = ServerLog.record(describeRequest(), exception);
            return ApiSupport.error(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                    "Internal error: " + exception.getMessage() +
                    " (error_id " + errorId + " — the full stack trace is in the server log; " +
                    "GET /health reports its path)",
                    errorId);
        }

        /** e.g. {@code "POST /tool/run_script"}; falls back gracefully outside a request. */
        private String describeRequest() {
            String method = request != null ? request.getMethod() : "?";
            String path = uriInfo != null ? "/" + uriInfo.getPath() : "?";
            return method + " " + path;
        }

        /**
         * A 404 on this server almost always means one thing: a tool name that does not exist.
         * Say that, and name the closest real tool, rather than echoing "HTTP 404 Not Found".
         */
        private String unknownEndpointMessage() {
            String path = uriInfo != null ? uriInfo.getPath() : "";
            String requested = path.startsWith("tool/") ? path.substring("tool/".length()) : null;

            StringBuilder message = new StringBuilder("Unknown endpoint '" + describeRequest() + "'. ");
            if (requested == null) {
                message.append("This server exposes /health, /schema, /openapi.json and ")
                        .append("GET|POST /tool/<tool_name>.");
                return message.toString();
            }

            message.append("There is no tool named '").append(requested).append("'.");
            String suggestion = ApiSupport.suggestClosest(requested, toolNames());
            if (suggestion != null) {
                message.append(" Did you mean '").append(suggestion).append("'?");
            } else {
                message.append(" Call GET /schema for the full tool list.");
            }
            return message.toString();
        }

        private static Set<String> toolNames() {
            Set<String> names = new TreeSet<>();
            names.addAll(ToolHelpers.listEndpoints(ReadTools.class));
            names.addAll(ToolHelpers.listEndpoints(WriteTools.class));
            names.addAll(ToolHelpers.listEndpoints(ScriptTool.class));
            return names;
        }
    }
}
