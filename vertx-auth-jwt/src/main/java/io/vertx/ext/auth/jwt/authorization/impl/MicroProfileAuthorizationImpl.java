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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.jwt.authorization.MicroProfileAuthorization;

import java.util.HashSet;
import java.util.Set;

/**
 * Default implementation for Micro Profile JWT 1.1
 */
public class MicroProfileAuthorizationImpl implements MicroProfileAuthorization {

  @Override
  public String getId() {
    return "mp-jwt";
  }

  @Override
  public void getAuthorizations(io.vertx.ext.auth.user.User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizations(user)
      .onComplete(handler);
  }

  @Override
  public Future<Void> getAuthorizations(io.vertx.ext.auth.user.User user) {
    final JsonObject accessToken = user.attributes().getJsonObject("accessToken");

    if (accessToken == null) {
      return Future.failedFuture("User doesn't contain a decoded Token");
    }

    final Set<Authorization> authorizations = new HashSet<>();

    // the spec MP-JWT 1.1 defines a custom grant called "groups"
    final JsonArray groups = accessToken.getJsonArray("groups");
    // This MP-JWT custom claim is the list of group names that have been assigned to the principal of the MP-JWT.
    // This typically will required a mapping at the application container level to application deployment roles,
    // but a a one-to-one between group names and application role names is required to be performed in addition
    // to any other mapping.

    if (groups != null && groups.size() >= 0) {
      for (Object el : groups) {
        // convert to the authorization type
        if (el instanceof String) {
          authorizations.add(RoleBasedAuthorization.create((String) el));
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
}
