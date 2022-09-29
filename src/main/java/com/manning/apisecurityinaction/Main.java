package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.controller.SpaceController;
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

        var spaceController = new SpaceController(database);

        post("/spaces", spaceController::createSpace);

        notFound(new JSONObject().put("notfound", "just a 404").toString());
        exception(IllegalArgumentException.class, Main::badRequest);
        internalServerError(new JSONObject().put("error", "internal server error").toString());

        afterAfter((req, res) -> {
            res.type("application/json");
            res.header("Server", "");
            res.header("X-XSS-Protection", "0");
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
        } catch (URISyntaxException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
