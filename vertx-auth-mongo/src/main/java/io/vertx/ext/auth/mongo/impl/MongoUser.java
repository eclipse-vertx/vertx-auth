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

import java.util.Collections;
import java.util.Set;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.MongoAuth;

/**
 * An implementation of {@link User} for use with {@link MongoAuth} is using the {@link JsonObject} which was loaded
 * from a MongoDb
 * 
 * @author mremme
 */
public class MongoUser extends AbstractUser {
  private JsonObject principal;
  private MongoAuth mongoAuth;

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
  public Set<Authorization> authorizations() {
	return Collections.emptySet();
  }

  /*
   * (non-Javadoc)
   * 
   * @see io.vertx.ext.auth.AbstractUser#doIsPermitted(java.lang.String, io.vertx.core.Handler)
   */
  @Override
  public void doIsPermitted(String permissionOrRole, Handler<AsyncResult<Boolean>> resultHandler) {
    if (permissionOrRole != null && permissionOrRole.startsWith(MongoAuth.ROLE_PREFIX)) {
      String roledef = permissionOrRole.substring(MongoAuth.ROLE_PREFIX.length());
      doHasRole(roledef, resultHandler);
    } else {
      doHasPermission(permissionOrRole, resultHandler);
    }
  }

  /*
   * (non-Javadoc)
   * 
   * @see io.vertx.ext.auth.User#principal()
   */
  @Override
  public JsonObject principal() {
    return principal;
  }

  /*
   * (non-Javadoc)
   * 
   * @see io.vertx.ext.auth.User#setAuthProvider(io.vertx.ext.auth.AuthProvider)
   */
  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    this.mongoAuth = (MongoAuth) authProvider;
  }

  /**
   * check wether the current user has the given role
   * 
   * @param role
   *          the role to be checked
   * @param resultHandler
   *          resultHandler gets true, if role is valid, otherwise false
   */
  protected void doHasRole(String role, Handler<AsyncResult<Boolean>> resultHandler) {
    try {
      JsonArray roles = principal.getJsonArray(mongoAuth.getRoleField());
      resultHandler.handle(Future.succeededFuture(roles != null && roles.contains(role)));
    } catch (Throwable e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  /**
   * Fetch the salt for the current user. This method is called, if the salt is defined to be stored inside the user
   * itself by {@link io.vertx.ext.auth.mongo.HashSaltStyle#COLUMN}
   * 
   * @return the salt, if it was stored inside a column, or null
   */
  public String getSalt() {
    return principal.getString(mongoAuth.getSaltField());
  }

  /**
   * Get the password, which is stored inside the user profile
   * 
   * @return the password from the current instance
   */
  public String getPassword() {
    return principal.getString(mongoAuth.getPasswordField());
  }

  /**
   * Check wether the current user has the given permission
   * 
   * @param permission
   *          the permission to be checked
   * @param resultHandler
   *          resulthandler gets true, if permission is valid, otherwise false
   * 
   */
  protected void doHasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    try {
      JsonArray userPermissions = principal.getJsonArray(mongoAuth.getPermissionField());
      resultHandler.handle(Future.succeededFuture(userPermissions != null && userPermissions.contains(permission)));
    } catch (Throwable e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  @Override
  public String toString() {
    return principal.toString();
  }
}
