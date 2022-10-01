package com.manning.apisecurityinaction.controller;

import com.lambdaworks.crypto.SCryptUtil;
import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.lambdaworks.crypto.SCryptUtil.*;

public class UserController {
    private static final String USERNAME_PATTERN = "[a-zA-Z][a-zA-Z0-9]{1,29}";
    private final Database database;

    public UserController(Database database){
        this.database = database;
    }

    public JSONObject registerUser(Request req, Response resp){
        var body = new JSONObject(req.body());
        var username = body.getString("username");
        var password = body.getString("password");

        if (!username.matches(USERNAME_PATTERN)){
            throw new IllegalArgumentException("The username invalid");
        }
        if (password.length() < 8){
            throw new IllegalArgumentException("Password should have at least 8 characters");
        }

        var hash = scrypt(password, 32768, 8, 1);

        database.updateUnique("INSERT INTO users (user_id, pw_hash) VALUES (?, ?)",
                username, hash);

        resp.status(201);
        resp.header("Location", "/users/" + username);
        return new JSONObject().put("username", username);
    }

    public void authenticate(Request req, Response resp){
        var authHeader = req.headers("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic ")){
            return;
        }

        int offset = "Basic ".length();
        var credentials = new String(Base64.getDecoder().decode(authHeader.substring(offset)), StandardCharsets.UTF_8);
        var components = credentials.split(":", 2);
        var username = components[0];
        var password = components[1];

        if (!username.matches(USERNAME_PATTERN)) {
            throw new IllegalArgumentException("Invalid username");
        }

        var hash = database.findOptional(String.class, "select pw_hash from users where user_id = ?", username);

        if (hash.isPresent() && SCryptUtil.check(password, hash.get())){
            req.attribute("subject", username);
        }
    }
}
