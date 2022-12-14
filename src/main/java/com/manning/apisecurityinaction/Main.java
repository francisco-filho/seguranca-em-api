package com.manning.apisecurityinaction;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.AuditController;
import com.manning.apisecurityinaction.controller.SpaceController;
import com.manning.apisecurityinaction.controller.UserController;
import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static spark.Spark.*;

public class Main {
    public static void main(String[] args) {
        var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);

        secure("localhost.p12", "changeit", null, null);

        var rateLimiter = RateLimiter.create(2.0d);
        before((req, res) -> {
            if (!rateLimiter.tryAcquire()) {
                res.header("Retry-After", "2");
                halt(429);
            }
        });

        var spaceController = new SpaceController(database);
        var userController = new UserController(database);
        var auditController = new AuditController(database);

        before(userController::authenticate);
        before(auditController::auditRequestStart);

        post("/users", userController::registerUser);
        post("/spaces", spaceController::createSpace);
        get("/logs", auditController::readAuditLog);

        notFound(new JSONObject().put("notfound", "just a 404").toString());
        exception(IllegalArgumentException.class, Main::badRequest);
        internalServerError(new JSONObject().put("error", "internal server error").toString());

        afterAfter(auditController::auditRequestEnd);

        afterAfter((req, res) -> {
            res.type("application/json");
            res.header("Server", "");
            res.header("", "nosniff");
            res.header("X-XSS-Protection", "0");
            res.header("Strict-Transport-Security", "max-age=3600");
        });
    }

    private static void badRequest(Exception ex, Request request, Response response) {
        response.status(400);
        response.body(new JSONObject().put("error", ex.getMessage()).toString());
    }

    private static void createTables(Database database) {
        try {
            Path schemaPath = Paths.get(Main.class.getResource("/schema.sql").toURI());
            database.update(Files.readString(schemaPath));
        } catch (URISyntaxException | IOException | NullPointerException e) {
            throw new RuntimeException(e);
        }
    }
}
