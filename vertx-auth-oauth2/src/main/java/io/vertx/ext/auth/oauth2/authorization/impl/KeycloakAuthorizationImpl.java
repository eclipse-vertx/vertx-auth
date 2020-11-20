/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.oauth2.authorization.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.oauth2.authorization.KeycloakAuthorization;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class KeycloakAuthorizationImpl implements KeycloakAuthorization {

  private static final JsonObject EMPTY_JSON = new JsonObject(Collections.emptyMap());

  @Override
  public String getId() {
    return "keycloak";
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    final JsonObject accessToken = user.attributes().getJsonObject("accessToken");

    if (accessToken == null) {
      handler.handle(Future.failedFuture("User doesn't contain a decoded Token"));
      return;
    }

    final Set<Authorization> authorizations = new HashSet<>();
    // a keycloak token contains 2 sources of authorizations:

    // 1. application roles
    try {
      extractApplicationRoles(accessToken, authorizations);
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
      return;
    }
    // 2. realm roles
    try {
      extractRealmRoles(accessToken, authorizations);
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
      return;
    }

    user.authorizations().add(getId(), authorizations);
    // return
    handler.handle(Future.succeededFuture());
  }

  private static void extractApplicationRoles(JsonObject accessToken, Set<Authorization> authorizations) {
    JsonObject resourceAccess = accessToken
      .getJsonObject("resource_access", EMPTY_JSON);

    for (String resource : resourceAccess.fieldNames()) {
      JsonArray appRoles = resourceAccess
        // locate the right resource
        .getJsonObject(resource, EMPTY_JSON)
        // locate the role list
        .getJsonArray("roles");

      if (appRoles != null && appRoles.size() >= 0) {
        for (Object el : appRoles) {
          // convert to the authorization type
          authorizations.add(
            RoleBasedAuthorization
              .create((String) el)
              // fix it to the right resource
              .setResource(resource));
        }
      }
    }
  }

  private static void extractRealmRoles(JsonObject accessToken, Set<Authorization> authorizations) {
    JsonArray appRoles = accessToken
      .getJsonObject("realm_access", EMPTY_JSON)
      // locate the role list
      .getJsonArray("roles");

    if (appRoles != null && appRoles.size() >= 0) {
      for (Object el : appRoles) {
        // convert to the authorization type
        authorizations.add(RoleBasedAuthorization.create((String) el));
      }
    }
  }
}
