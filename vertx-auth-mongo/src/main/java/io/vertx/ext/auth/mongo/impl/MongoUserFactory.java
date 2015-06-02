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

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.HashStrategy.SaltStyle;
import io.vertx.ext.auth.mongo.MongoAuth;
import io.vertx.ext.auth.mongo.UserFactory;

import java.util.List;

/**
 * Implementation of {@link UserFactory} creates instances of {@link MongoUser}
 * 
 * @author mremme
 */

public class MongoUserFactory implements UserFactory {

  /**
   * 
   */
  public MongoUserFactory() {
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.UserFactory#createUser(java.lang.String, io.vertx.ext.auth.AuthProvider)
   */
  @Override
  public User createUser(String username, AuthProvider authProvider) {
    return createUser(username, null, null, null, authProvider);
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.UserFactory#createUser(java.lang.String, java.lang.String, java.util.List, java.util.List, io.vertx.ext.auth.AuthProvider)
   */
  @Override
  public User createUser(String username, String password, List<String> roles, List<String> permissions,
      AuthProvider authProvider) {
    MongoAuth mAuth = (MongoAuth) authProvider;
    JsonObject principal = new JsonObject();
    principal.put(mAuth.getUsernameField(), username);

    if (roles != null) {
      principal.put(MongoAuth.DEFAULT_ROLE_FIELD, new JsonArray(roles));
    }

    if (permissions != null) {
      principal.put(MongoAuth.DEFAULT_PERMISSION_FIELD, new JsonArray(permissions));
    }
    MongoUser user = (MongoUser) createUser(principal, authProvider);

    if (mAuth.getHashStrategy().getSaltStyle() == SaltStyle.COLUMN) {
      principal.put(mAuth.getSaltField(), DefaultHashStrategy.generateSalt());
    }

    String cryptPassword = mAuth.getHashStrategy().computeHash(password, user);
    principal.put(mAuth.getPasswordField(), cryptPassword);
    return user;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.UserFactory#createUser(io.vertx.core.json.JsonObject, io.vertx.ext.auth.AuthProvider)
   */
  @Override
  public User createUser(JsonObject principal, AuthProvider authProvider) {
    MongoAuth mAuth = (MongoAuth) authProvider;
    return new MongoUser(principal, (MongoAuth) authProvider);
  }

}
