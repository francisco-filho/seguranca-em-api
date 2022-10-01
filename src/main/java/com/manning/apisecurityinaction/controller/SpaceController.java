package com.manning.apisecurityinaction.controller;

import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

public class SpaceController {
    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    public JSONObject createSpace(Request req, Response res){
        var body = new JSONObject(req.body());
        var spaceName = body.getString("name");
        if (spaceName.length() > 255){
            throw new IllegalArgumentException("The length of the name should be less than 255 characters");
        }
        var owner = body.getString("owner");
        if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")){
            throw new IllegalArgumentException("The owner name should have only letters and numbers");
        }

        var subject = req.attribute("subject");
        if (!owner.equals(subject)){
            throw new IllegalArgumentException("The owner of the namespace should be the loggedIn user");
        }

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq");

            database.updateUnique("INSERT INTO spaces (space_id, name, owner) VALUES (?, ?, ?)",
                    spaceId, spaceName, owner);

            res.status(201);
            res.header("Location", "/spaces/" + spaceId);
            return new JSONObject()
                    .put("name", spaceName)
                    .put("uri", "/spaces/" + spaceId );
        });
    }
}
