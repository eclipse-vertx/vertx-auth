/*
 * Copyright (c) 2025 Sanju Thomas
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
package io.vertx.tests;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.DCROptions;
import io.vertx.ext.auth.oauth2.DCRRequest;
import io.vertx.ext.auth.oauth2.DCRResponse;
import io.vertx.ext.auth.oauth2.dcr.KeycloakClientRegistration;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunnerWithParametersFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;
import org.testcontainers.containers.wait.strategy.Wait;

public class DCRKeycloak25_0_0_IT {

    private static final String REALM = "master";
    @Rule
    public final RunTestOnContext rule = new RunTestOnContext();

    private static GenericContainer<?> keycloak;

    @BeforeClass
    public static void setupDocker() {
        keycloak = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:25.0.0"))
                .withExposedPorts(8080)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "secret")
                .withCommand("start-dev")
                .waitingFor(
                        Wait.forHttp(String.format("/realms/%s/.well-known/openid-configuration", REALM))
                                .forStatusCode(200)
                                .withStartupTimeout(Duration.ofSeconds(90)));
    }

    @Before
    public void setup() {
        keycloak.start();
    }

    @After
    public void tearDown() {
        keycloak.stop();
    }

    @Test
    public void testCreateDynamicClient() throws Exception {
        String baseUrl = String.format("http://%s:%s", keycloak.getHost(), keycloak.getMappedPort(8080));
        String initialAccessToken = createInitialAccessToken(baseUrl,
                getAdminAccessToken(baseUrl).await(10, TimeUnit.SECONDS))
                .await(10, TimeUnit.SECONDS);
        JsonObject options = new JsonObject().put("site", baseUrl).put("tenant", REALM).put("initialAccessToken",
                initialAccessToken);
        KeycloakClientRegistration keycloakClientRegistration = KeycloakClientRegistration.create(rule.vertx(),
                new DCROptions(options));
        Future<DCRResponse> dcrResponse = keycloakClientRegistration.create("junit-test-client");
        DCRResponse client = dcrResponse.await(10, TimeUnit.SECONDS);
        assertNotNull(client.getId());
        assertEquals("junit-test-client", client.getClientId());
        assertEquals("client-secret", client.getClientAuthenticatorType());
        assertNotNull(client.getRegistrationAccessToken());
        assertNotNull(client.getSecret());
    }

    @Test
    public void testGetDynamicClient() throws Exception {
        String baseUrl = String.format("http://%s:%s", keycloak.getHost(), keycloak.getMappedPort(8080));
        String initialAccessToken = createInitialAccessToken(baseUrl,
                getAdminAccessToken(baseUrl).await(10, TimeUnit.SECONDS))
                .await(10, TimeUnit.SECONDS);
        JsonObject options = new JsonObject().put("site", baseUrl).put("tenant", REALM).put("initialAccessToken",
                initialAccessToken);
        KeycloakClientRegistration keycloakClientRegistration = KeycloakClientRegistration.create(rule.vertx(),
                new DCROptions(options));
        Future<DCRResponse> dcrResponse = keycloakClientRegistration.create("junit-test-client");
        DCRResponse client = dcrResponse.await(10, TimeUnit.SECONDS);
        assertNotNull(client.getId());
        assertEquals("junit-test-client", client.getClientId());
        JsonObject requJsonObject = new JsonObject().put("registrationAccessToken", client.getRegistrationAccessToken())
                .put("clientId", "junit-test-client");
        DCRRequest dcrRequest = new DCRRequest(requJsonObject);
        DCRResponse getResopnse = keycloakClientRegistration.get(dcrRequest).await(10, TimeUnit.SECONDS);
        assertEquals("junit-test-client", getResopnse.getClientId());
        assertEquals(client.getRegistrationAccessToken(), getResopnse.getRegistrationAccessToken());
    }

    @Test
    public void testDleteDynamicClient() throws Exception {
        String baseUrl = String.format("http://%s:%s", keycloak.getHost(), keycloak.getMappedPort(8080));
        String initialAccessToken = createInitialAccessToken(baseUrl,
                getAdminAccessToken(baseUrl).await(10, TimeUnit.SECONDS))
                .await(10, TimeUnit.SECONDS);
        JsonObject options = new JsonObject().put("site", baseUrl).put("tenant", REALM).put("initialAccessToken",
                initialAccessToken);
        KeycloakClientRegistration keycloakClientRegistration = KeycloakClientRegistration.create(rule.vertx(),
                new DCROptions(options));
        Future<DCRResponse> dcrResponse = keycloakClientRegistration.create("junit-test-client");
        DCRResponse client = dcrResponse.await(10, TimeUnit.SECONDS);
        assertNotNull(client.getId());
        assertEquals("junit-test-client", client.getClientId());
        JsonObject requJsonObject = new JsonObject().put("registrationAccessToken", client.getRegistrationAccessToken())
                .put("clientId", "junit-test-client");
        DCRRequest dcrRequest = new DCRRequest(requJsonObject);
        DCRResponse getResopnse = keycloakClientRegistration.get(dcrRequest).await(10, TimeUnit.SECONDS);
        assertEquals("junit-test-client", getResopnse.getClientId());
        assertEquals(client.getRegistrationAccessToken(), getResopnse.getRegistrationAccessToken());
        keycloakClientRegistration.delete(dcrRequest).await(10, TimeUnit.SECONDS);
        keycloakClientRegistration.get(dcrRequest).onFailure(load -> {
            assertEquals(
                    "Unauthorized: {\"error\":\"invalid_token\",\"error_description\":\"Not authorized to view client. Not valid token or client credentials provided.\"}",
                    load.getMessage());
        });
    }

    private Future<String> getAdminAccessToken(String baseUrl) throws Exception {
        SimpleHttpClient simpleHttpClient = new SimpleHttpClient(rule.vertx(), baseUrl, new HttpClientOptions());
        JsonObject header = new JsonObject().put("Content-Type", "application/x-www-form-urlencoded");
        Buffer body = Buffer.buffer("grant_type=password&client_id=admin-cli&username=admin&password=secret");
        return simpleHttpClient
                .fetch(HttpMethod.POST, String.format("%s/realms/%s/protocol/openid-connect/token", baseUrl, REALM),
                        header,
                        body)
                .compose(response -> Future.succeededFuture(response.jsonObject().getString("access_token")));
    }

    private Future<String> createInitialAccessToken(String baseUrl, String adminBearer) throws Exception {
        CompletableFuture<String> future = new CompletableFuture<>();
        JsonObject header = new JsonObject().put("Authorization", String.format("Bearer %s", adminBearer))
                .put("Content-Type", "application/json");
        JsonObject payload = new JsonObject()
                .put("expiration", 180)
                .put("count", 1);
        SimpleHttpClient simpleHttpClient = new SimpleHttpClient(rule.vertx(), baseUrl, new HttpClientOptions());
        return simpleHttpClient
                .fetch(HttpMethod.POST, String.format("%s/admin/realms/%s/clients-initial-access", baseUrl, REALM),
                        header, payload.toBuffer())
                .compose(response -> Future.succeededFuture(response.jsonObject().getString("token")));
    }
}
