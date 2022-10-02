package com.manning.apisecurityinaction.controller;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class AuditController {
    private final Database database;

    public AuditController(Database database) {
        this.database = database;
    }

    public void auditRequestStart(Request req, Response resp){
        database.withVoidTransaction((tx) -> {
            var auditId = database.findUniqueLong("select next value for audit_id_seq");
            req.attribute("audit_id", auditId);
            database.updateUnique(
                    "INSERT INTO audit_log(audit_id, method, path, " +
                            "user_id, audit_time) " +
                            "VALUES(?, ?, ?, ?, current_timestamp)",
                    auditId,
                    req.requestMethod(),
                    req.pathInfo(),
                    req.attribute("subject")
                    );
        });

    }

    public void auditRequestEnd(Request req, Response resp){
        var auditId = req.attribute("audit_id");
        database.updateUnique(
                "INSERT INTO audit_log(audit_id, method, path, " +
                        "user_id, audit_time) " +
                        "VALUES(?, ?, ?, ?, current_timestamp)",
                auditId,
                req.requestMethod(),
                req.pathInfo(),
                req.attribute("subject")
        );
    }

    public JSONArray readAuditLog(Request req, Response resp){
        var since = Instant.now().minus(1, ChronoUnit.HOURS);
        var sql = "select * from audit_log where audit_time >= ? order by audit_time desc";
        var logs = database.findAll(AuditController::recordToJson, sql, since);
        return new JSONArray(logs);
    }

    private static JSONObject recordToJson(ResultSet row) throws SQLException {
        return new JSONObject()
            .put("id", row.getLong("audit_id"))
            .put("method", row.getString("method"))
            .put("path", row.getString("path"))
            .put("status", row.getInt("status"))
            .put("user", row.getString("user_id"))
            .put("time", row.getTimestamp("audit_time").toInstant());
    }
}
