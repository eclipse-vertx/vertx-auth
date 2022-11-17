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
package io.vertx.ext.auth.jwt.authorization.impl;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.jwt.authorization.JWTAuthorization;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class JWTAuthorizationImpl implements JWTAuthorization {

  private final String rootClaim;

  public JWTAuthorizationImpl(String rootClaim) {
    this.rootClaim = Objects.requireNonNull(rootClaim, "rootClaim cannot be null");
  }

  @Override
  public String getId() {
    return "jwt";
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizations(user)
      .onComplete(handler);
  }

  @Override
  public Future<Void> getAuthorizations(User user) {

    final JsonArray roles;

    if (rootClaim.contains("/")) {
      try {
        roles = getNestedJsonValue(user.attributes().getJsonObject("accessToken"), rootClaim);
      } catch (RuntimeException e) {
        return Future.failedFuture(e);
      }
    } else {
      try {
        roles = user.attributes().getJsonObject("accessToken").getJsonArray(rootClaim);
      } catch (RuntimeException e) {
        return Future.failedFuture(e);
      }
    }

    final Set<Authorization> authorizations = new HashSet<>();

    if (roles != null && roles.size() >= 0) {
      for (Object el : roles) {
        // convert to the authorization type
        if (el instanceof String) {
          authorizations.add(PermissionBasedAuthorization.create((String) el));
        } else {
          // abort the parsing
          return Future.failedFuture("Cannot parse role: " + el);
        }
      }
    }
    user.authorizations().add(getId(), authorizations);
    // return
    return Future.succeededFuture();
  }

  private static @Nullable JsonArray getNestedJsonValue(JsonObject jwtToken, String permissionsClaimKey) {
    String[] keys = permissionsClaimKey.split("/");
    JsonObject obj = null;
    for (int i = 0; i < keys.length; i++) {
      if (i == 0) {
        obj = jwtToken.getJsonObject(keys[i]);
      } else if (i == keys.length - 1) {
        if (obj != null) {
          return obj.getJsonArray(keys[i]);
        }
      } else {
        if (obj != null) {
          obj = obj.getJsonObject(keys[i]);
        }
      }
    }
    return null;
  }
}
