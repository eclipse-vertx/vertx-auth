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
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.AbstractUser;

import java.util.Set;

/**
 * @author Paulo Lopes
 */
public final class JWTUser extends AbstractUser {

  private static final Logger log = LoggerFactory.getLogger(JWTUser.class);

  private final JsonObject jwtToken;

  private final JsonArray roles;
  private final JsonArray permissions;

  public JWTUser(JsonObject jwtToken, String rolesClaimKey, String permissionsClaimKey) {
    this.jwtToken = jwtToken;

    this.roles = jwtToken.getJsonArray(rolesClaimKey, null);
    this.permissions = jwtToken.getJsonArray(permissionsClaimKey, null);
  }

  @Override
  public JsonObject principal() {
    return jwtToken;
  }

  @Override
  public boolean isClusterable() {
    return false;
  }

  @Override
  protected void doHasRole(String role, Handler<AsyncResult<Boolean>> handler) {
    if (roles != null) {
      for (Object jwtRole : roles) {
        if (role.equals(jwtRole)) {
          handler.handle(Future.succeededFuture(true));
          return;
        }
      }
    }

    log.debug("User has no role [" + role + "]");
    handler.handle(Future.succeededFuture(false));
  }

  @Override
  public void doHasRoles(Set<String> roles, Handler<AsyncResult<Boolean>> handler) {
    if (this.roles != null) {
      for (String role : roles) {
        boolean found = false;

        for (Object jwtRole : this.roles) {
          if (role.equals(jwtRole)) {
            found = true;
            break;
          }
        }

        if (!found) {
          log.debug("User has no role [" + role + "]");
          handler.handle(Future.succeededFuture(false));
          return;
        }
      }
    }

    handler.handle(Future.succeededFuture(true));
  }

  @Override
  public void doHasPermission(String permission, Handler<AsyncResult<Boolean>> handler) {
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

  @Override
  public void doHasPermissions(Set<String> permissions, Handler<AsyncResult<Boolean>> handler) {
    if (this.permissions != null) {
      for (String permission : permissions) {
        boolean found = false;

        for (Object jwtPermission : this.permissions) {
          if (permission.equals(jwtPermission)) {
            found = true;
            break;
          }
        }

        if (!found) {
          log.debug("User has no permission [" + permission + "]");
          handler.handle(Future.succeededFuture(false));
          return;
        }
      }
    }

    handler.handle(Future.succeededFuture(true));
  }
}
