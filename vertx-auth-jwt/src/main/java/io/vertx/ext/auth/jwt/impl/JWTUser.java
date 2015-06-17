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
package io.vertx.ext.auth.jwt.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;

/**
 * @author Paulo Lopes
 */
public final class JWTUser extends AbstractUser {

  private static final Logger log = LoggerFactory.getLogger(JWTUser.class);

  private final JsonObject jwtToken;

  private final JsonArray permissions;

  public JWTUser(JsonObject jwtToken, String permissionsClaimKey) {
    this.jwtToken = jwtToken;

    this.permissions = jwtToken.getJsonArray(permissionsClaimKey, null);
  }

  @Override
  public JsonObject principal() {
    return jwtToken;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    // NOOP - JWT tokens are self contained :)
  }

  @Override
  public void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> handler) {
    if (permissions != null) {
      for (Object jwtPermission : permissions) {
        if (permission.equals(jwtPermission)) {
          handler.handle(Future.succeededFuture(true));
          return;
        }
      }
    }

    log.debug("User has no permission [" + permission + "]");
    handler.handle(Future.succeededFuture(false));
  }
}
