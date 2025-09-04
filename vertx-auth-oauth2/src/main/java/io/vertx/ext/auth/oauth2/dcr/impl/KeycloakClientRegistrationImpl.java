package io.vertx.ext.auth.oauth2.dcr.impl;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.impl.http.SimpleHttpResponse;
import io.vertx.ext.auth.oauth2.DCROptions;
import io.vertx.ext.auth.oauth2.DCRRequest;
import io.vertx.ext.auth.oauth2.DCRResponse;
import io.vertx.ext.auth.oauth2.dcr.KeycloakClientRegistration;

public final class KeycloakClientRegistrationImpl implements KeycloakClientRegistration {

  private final Vertx vertx;
  private final SimpleHttpClient simpleHttpClient;

  private final DCROptions dcrOptions;

  public KeycloakClientRegistrationImpl(Vertx vertx, DCROptions dcrOptions) {
    this.vertx = vertx;
    this.dcrOptions = dcrOptions;
    this.simpleHttpClient = new SimpleHttpClient(vertx, "dcr-client", dcrOptions.getHttpClientOptions());
  }

  @Override
  public Future<DCRResponse> create(String clientId) {
    JsonObject initialAccessToken = JsonObject.of("Authorization", String.format("Bearer %s", dcrOptions.getInitialAccessToken()));
    JsonObject payload = JsonObject.of("clientId", clientId);
    return simpleHttpClient.fetch(HttpMethod.POST, dcrOptions.resourceUri(), initialAccessToken,
      payload.toBuffer()).compose(response -> constructResponse(response));
  }
  @Override
  public Future<DCRResponse> get(DCRRequest dcrRequest) {
    JsonObject registrationToken = JsonObject.of("Authorization", String.format("Bearer %s", dcrRequest.getRegistrationAccessToken()));
    return simpleHttpClient.fetch(HttpMethod.GET, String.format("%s/%s", dcrOptions.resourceUri(),
        dcrRequest.getClientId()), registrationToken, null)
      .compose(response -> constructResponse(response));
  }

  @Override
  public Future<Void> delete(DCRRequest dcrRequest) {
    JsonObject registrationToken = JsonObject.of("Authorization", String.format("Bearer %s", dcrRequest.getRegistrationAccessToken()));
    return simpleHttpClient.fetch(HttpMethod.DELETE, String.format("%s/%s", dcrOptions.resourceUri(),
        dcrRequest.getClientId()), registrationToken, null)
      .compose(response -> {
        if (response.statusCode() != 204) {
          return Future.failedFuture("Bad Response [" + response.statusCode() + "] " + response.body());
        }
        return Future.succeededFuture();
      });
  }

  private Future<DCRResponse> constructResponse(SimpleHttpResponse response) {
    if (response.statusCode() != 201) {
      return Future.failedFuture("Bad Response [" + response.statusCode() + "] " + response.body());
    }
    if (!response.is("application/json")) {
      return Future.failedFuture("Cannot handle Content-Type: " + response.headers().get("Content-Type"));
    }
    final JsonObject json = response.jsonObject();
    if (json == null) {
      return Future.failedFuture("Cannot handle null JSON");
    }
    return Future.succeededFuture(new DCRResponse(json));
  }
}