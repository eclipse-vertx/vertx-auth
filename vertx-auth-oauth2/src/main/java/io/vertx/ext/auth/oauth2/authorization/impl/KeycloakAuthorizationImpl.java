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

  private static final JsonObject EMPTY_JSON = new JsonObject(Collections.EMPTY_MAP);

  @Override
  public String getId() {
    return "keycloak";
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Set<Authorization>>> handler) {
    final String rootClaim = user.attributes().getString("accessToken");
    final JsonObject accessToken =
      rootClaim == null ?
        user.principal() :
        user.principal().getJsonObject(rootClaim);

    if (accessToken == null) {
      handler.handle(Future.failedFuture("User doesn't contain a decoded Token"));
      return;
    }

    final Set<Authorization> authorizations = new HashSet<>();
    // a keycloak token contains 2 sources of authorizations:

    // 1. application roles
    try {
      extractRoles(accessToken, "resource_access", authorizations);
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
      return;
    }
    // 2. realm roles
    try {
      extractRoles(accessToken, "realm_access", authorizations);
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
      return;
    }

    // return
    handler.handle(Future.succeededFuture(authorizations));
  }

  private static void extractRoles(JsonObject accessToken, String access, Set<Authorization> authorizations) {
    JsonObject resourceAccess = accessToken
      .getJsonObject(access, EMPTY_JSON);

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
}
