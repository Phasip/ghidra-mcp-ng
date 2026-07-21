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
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
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
            StringBuilder message = new StringBuilder();
            message.append("Unknown query parameter")
                    .append(unknown.size() == 1 ? " " : "s ")
                    .append(quoteJoin(unknown))
                    .append(" for endpoint '").append(endpoint).append("'. ");
            if (allowed.isEmpty()) {
                message.append("This endpoint takes no query parameters.");
            } else {
                message.append("Valid parameters: ").append(String.join(", ", allowed)).append(".");
                String suggestion = suggestClosest(unknown.get(0), allowed);
                if (suggestion != null) {
                    message.append(" Did you mean '").append(suggestion)
                            .append("' (for '").append(unknown.get(0)).append("')?");
                }
            }
            requestContext.abortWith(ApiSupport.error(Response.Status.BAD_REQUEST, message.toString()));
        }

        private static String quoteJoin(List<String> values) {
            List<String> quoted = new ArrayList<>(values.size());
            for (String value : values) {
                quoted.add("'" + value + "'");
            }
            return String.join(", ", quoted);
        }

        /** Returns the allowed parameter closest to {@code provided}, or null if none is close. */
        private static String suggestClosest(String provided, Set<String> allowed) {
            String best = null;
            int bestDistance = Integer.MAX_VALUE;
            for (String candidate : allowed) {
                int distance = levenshtein(provided.toLowerCase(), candidate.toLowerCase());
                if (distance < bestDistance) {
                    bestDistance = distance;
                    best = candidate;
                }
            }
            // Only suggest when the names are genuinely similar (or one contains the other),
            // so we don't emit a misleading hint for a wholly unrelated parameter.
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
