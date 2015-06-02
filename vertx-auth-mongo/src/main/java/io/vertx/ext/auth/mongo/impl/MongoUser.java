/*
 * Copyright 2014 Red Hat, Inc.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 * 
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 * 
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.mongo.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.HashStrategy.SaltStyle;
import io.vertx.ext.auth.mongo.MongoAuth;

import java.util.Set;

/**
 * An implementation of {@link User} for use with {@link MongoAuth} is using the {@link JsonObject} which was loaded
 * from a MongoDb
 * 
 * @author mremme
 */
public class MongoUser extends AbstractUser {
  private JsonObject principal;
  private MongoAuth  mongoAuth;

  public MongoUser() {
  }

  public MongoUser(String username, MongoAuth mongoAuth) {
    this.principal = new JsonObject().put(mongoAuth.getUsernameField(), username);
    this.mongoAuth = mongoAuth;
  }

  public MongoUser(JsonObject principal, MongoAuth mongoAuth) {
    this.principal = principal;
    this.mongoAuth = mongoAuth;
  }

  @Override
  public void doIsPermitted(String permissionOrRole, Handler<AsyncResult<Boolean>> resultHandler) {
    if (permissionOrRole != null && permissionOrRole.startsWith(MongoAuth.ROLE_PREFIX)) {
      String roledef = permissionOrRole.substring(MongoAuth.ROLE_PREFIX.length());
      doHasRole(roledef, resultHandler);
    } else {
      doHasPermission(permissionOrRole, resultHandler);
    }
  }

  /**
   * 
   */
  @Override
  public JsonObject principal() {
    return principal;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    this.mongoAuth = (MongoAuth) authProvider;
  }

  /**
   * check wether the current user has the given role
   * 
   * @param role
   * @param resultHandler
   */
  protected void doHasRole(String role, Handler<AsyncResult<Boolean>> resultHandler) {
    try {
      JsonArray roles = readRoles();
      resultHandler.handle(Future.succeededFuture(roles != null && roles.contains(role)));
    } catch (Throwable e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  /**
   * Read the array of Roles from the declared field
   * 
   * @return
   */
  protected JsonArray readRoles() {
    return principal.getJsonArray(mongoAuth.getRoleField());
  }

  /**
   * Read the array of permissions from the declared field
   * 
   * @return
   */
  protected JsonArray readPermissions() {
    return principal.getJsonArray(mongoAuth.getPermissionField());
  }

  /**
   * Fetch the salt for the current user. This method is called, if the salt is defined to be stored inside the user
   * itself by {@link SaltStyle#COLUMN}
   * 
   * @return
   */
  public String getSalt() {
    return principal.getString(mongoAuth.getSaltField());
  }

  /**
   * Get the password, which is stored inside the user profile
   * 
   * @return
   */
  public String getPassword() {
    return principal.getString(mongoAuth.getPasswordField());
  }

  /**
   * Check wether the current user has the given permission
   * 
   * @param permission
   * @param resultHandler
   */
  protected void doHasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    try {
      JsonArray userPermissions = readPermissions();
      resultHandler.handle(Future.succeededFuture(userPermissions != null && userPermissions.contains(permission)));
    } catch (Throwable e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  /**
   * Check a series of roles
   * 
   * @param roles
   * @param resultHandler
   */
  protected void doHasRoles(Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    try {
      JsonArray userRoles = readPermissions();
      if (userRoles == null || userRoles.isEmpty()) {
        resultHandler.handle(Future.succeededFuture(false));
        return;
      }
      for (String role : roles) {
        if (!userRoles.contains(role)) {
          resultHandler.handle(Future.succeededFuture(false));
          return;
        }
      }
      resultHandler.handle(Future.succeededFuture(true));
    } catch (Throwable e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  /**
   * Check a series of permissions
   * 
   * @param permissions
   * @param resultHandler
   */
  protected void doHasPermissions(Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) {
    try {
      JsonArray userPermissions = readPermissions();
      if (userPermissions == null || userPermissions.isEmpty()) {
        resultHandler.handle(Future.succeededFuture(false));
        return;
      }
      for (String permission : permissions) {
        if (!userPermissions.contains(permission)) {
          resultHandler.handle(Future.succeededFuture(false));
          return;
        }
      }
      resultHandler.handle(Future.succeededFuture(true));
    } catch (Throwable e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  @Override
  public String toString() {
    return principal.toString();
  }
}
