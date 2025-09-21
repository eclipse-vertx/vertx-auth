package io.vertx.tests;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.DCROptions;
import io.vertx.ext.auth.oauth2.DCRResponse;
import io.vertx.ext.auth.oauth2.dcr.KeycloakClientRegistration;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunnerWithParametersFactory;

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

import org.junit.Before;
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

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testCreateDynamicClient() throws Exception {
    try (
        GenericContainer<?> keycloak = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:25.0.0"))
            .withExposedPorts(8080)
            .withEnv("KEYCLOAK_ADMIN", "admin")
            .withEnv("KEYCLOAK_ADMIN_PASSWORD", "secret")
            .withCommand("start-dev")
            .waitingFor(
                Wait.forHttp("/realms/master/.well-known/openid-configuration")
                    .forStatusCode(200)
                    .withStartupTimeout(Duration.ofSeconds(90)));) {
      keycloak.start();
      String baseUrl = String.format("http://%s:%s", keycloak.getHost(), keycloak.getMappedPort(8080));
      System.out.printf("Keycloak is running at %s", baseUrl);
      String accessToken = getAdminAccessToken(baseUrl).await(60, TimeUnit.SECONDS);
      System.out.println(accessToken);
    }
  }

  private Future<String> getAdminAccessToken(String baseUrl) throws Exception {
    SimpleHttpClient simpleHttpClient = new SimpleHttpClient(rule.vertx(), baseUrl, new HttpClientOptions());
    JsonObject header = new JsonObject().put("Content-Type", "application/x-www-form-urlencoded");
    Buffer body = Buffer.buffer("grant_type=password&client_id=admin-cli&username=admin&password=secret");
    return simpleHttpClient.fetch(HttpMethod.POST, baseUrl + "/realms/master/protocol/openid-connect/token", header, body)
        .compose(response -> Future.succeededFuture(response.jsonObject().getString("access_token")));
  }

}
