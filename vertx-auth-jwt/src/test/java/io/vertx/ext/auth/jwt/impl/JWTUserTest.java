package io.vertx.ext.auth.jwt.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.util.Arrays;

public class JWTUserTest extends VertxTestBase{
    @Test
    public void testNormalRoles() {
        JsonObject token = new JsonObject()
                        .put("roles", new JsonArray(Arrays.asList("role1", "role2")));

        JWTUser jwtUser = new JWTUser(token, "roles");
        jwtUser.isAuthorized("role1", r -> {
            assertTrue("should have role", r.result());
            testComplete();
        });

        await();
    }

    @Test
    public void testNormalRolesNoAccess() {
        JsonObject token = new JsonObject()
                .put("roles", new JsonArray(Arrays.asList("role1", "role2")));

        JWTUser jwtUser = new JWTUser(token, "roles");
        jwtUser.isAuthorized("role3", r -> {
            assertFalse("should not have role", r.result());
            testComplete();
        });

        await();
    }

    @Test
    public void testParseNestedRoles() {
        JsonObject token = new JsonObject()
                .put("realm", new JsonObject()
                        .put("roles", new JsonArray(Arrays.asList("role1", "role2"))));

        JWTUser jwtUser = new JWTUser(token, "realm/roles");
        jwtUser.isAuthorized("role1", r -> {
            assertTrue("should have role", r.result());
            testComplete();
        });

        await();
    }

    @Test
    public void testParseNestedRolesNoAccess() {
        JsonObject token = new JsonObject()
                .put("realm", new JsonObject()
                        .put("roles", new JsonArray(Arrays.asList("role1", "role2"))));

        JWTUser jwtUser = new JWTUser(token, "realm/roles");
        jwtUser.isAuthorized("role3", r -> {
            assertFalse("should not have role", r.result());
            testComplete();
        });

        await();
    }

    @Test
    public void testParseDeeplyNestedRoles() {
        JsonObject token = new JsonObject()
                .put("realm", new JsonObject()
                        .put("access", new JsonObject()
                        .put("roles", new JsonArray(Arrays.asList("role1", "role2")))));

        JWTUser jwtUser = new JWTUser(token, "realm/access/roles");
        jwtUser.isAuthorized("role1", r -> {
            assertTrue("should have role", r.result());
            testComplete();
        });

        await();
    }

    @Test
    public void testInvalidNestedKey() {
        JsonObject token = new JsonObject()
                .put("realm", new JsonObject()
                        .put("access", new JsonObject()
                                .put("roles", new JsonArray(Arrays.asList("role1", "role2")))));

        JWTUser jwtUser = new JWTUser(token, "realm/wrong/roles");
        jwtUser.isAuthorized("role1", r -> {
            assertFalse("should not have role", r.result());
            testComplete();
        });

        await();
    }
}
