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
import java.util.Objects;

public final class KeycloakClientRegistrationImpl implements KeycloakClientRegistration {

  private final SimpleHttpClient simpleHttpClient;

  private final DCROptions dcrOptions;

  public KeycloakClientRegistrationImpl(Vertx vertx, DCROptions dcrOptions) {
    Objects.requireNonNull(dcrOptions.getInitialAccessToken(), "initialAccessToken cannot be null");
    Objects.requireNonNull(dcrOptions.getSite(), "site cannot be null");
    Objects.requireNonNull(dcrOptions.getTenant(), "tenant cannot be null");
    this.dcrOptions = dcrOptions;
    this.simpleHttpClient = new SimpleHttpClient(vertx, "dcr-client", dcrOptions.getHttpClientOptions());
  }

  @Override
  public Future<DCRResponse> create(String clientId) {
    JsonObject initialAccessToken = JsonObject.of("Authorization",
        String.format("Bearer %s", dcrOptions.getInitialAccessToken()));
    JsonObject payload = JsonObject.of("clientId", clientId);
    return simpleHttpClient.fetch(HttpMethod.POST, dcrOptions.resourceUri(), initialAccessToken,
        payload.toBuffer()).compose(response -> constructResponse(response, 201));
  }

  @Override
  public Future<DCRResponse> get(DCRRequest dcrRequest) {
    Objects.requireNonNull(dcrRequest.getClientId(), "clientId cannot be null.");
    Objects.requireNonNull(dcrRequest.getRegistrationAccessToken(), "registrationAccessToken cannot be null.");
    JsonObject registrationToken = JsonObject.of("Authorization",
        String.format("Bearer %s", dcrRequest.getRegistrationAccessToken()));
    return simpleHttpClient.fetch(HttpMethod.GET, String.format("%s/%s", dcrOptions.resourceUri(),
        dcrRequest.getClientId()), registrationToken, null)
        .compose(response -> constructResponse(response, 200));
  }

  @Override
  public Future<Void> delete(DCRRequest dcrRequest) {
    Objects.requireNonNull(dcrRequest.getClientId(), "clientId cannot be null.");
    Objects.requireNonNull(dcrRequest.getRegistrationAccessToken(), "registrationAccessToken cannot be null.");
    JsonObject registrationToken = JsonObject.of("Authorization",
        String.format("Bearer %s", dcrRequest.getRegistrationAccessToken()));
    return simpleHttpClient.fetch(HttpMethod.DELETE, String.format("%s/%s", dcrOptions.resourceUri(),
        dcrRequest.getClientId()), registrationToken, null)
        .compose(response -> {
          if (response.statusCode() != 204) {
            return Future.failedFuture("Bad Response [" + response.statusCode() + "] " + response.body());
          }
          return Future.succeededFuture();
        });
  }

  private Future<DCRResponse> constructResponse(SimpleHttpResponse response, int expectedStatusCode) {
    if (response.statusCode() != expectedStatusCode) {
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