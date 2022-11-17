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
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.mongo.*;
import io.vertx.ext.mongo.MongoClient;

import java.util.Objects;

/**
 * An implementation of {@link MongoAuthorization}
 *
 * @author mremme
 */
public class MongoAuthorizationImpl implements MongoAuthorization {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthorizationImpl.class);
  private final MongoClient mongoClient;
  private final String providerId;
  private final MongoAuthorizationOptions options;

  /**
   * Creates a new instance
   *
   * @param providerId  the provider ID to differentiate from others
   * @param mongoClient the {@link MongoClient} to be used
   * @param options     the options for configuring the new instance
   */
  public MongoAuthorizationImpl(String providerId, MongoClient mongoClient, MongoAuthorizationOptions options) {
    this.providerId = Objects.requireNonNull(providerId);
    this.mongoClient = mongoClient;
    this.options = options;
  }

  /**
   * The default implementation uses the usernameField as search field
   *
   * @param username
   * @return
   */
  protected JsonObject createQuery(String username) {
    return new JsonObject().put(options.getUsernameField(), username);
  }

  @Override
  public String getId() {
    return providerId;
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizations(user)
      .onComplete(handler);
  }

  @Override
  public Future<Void> getAuthorizations(User user) {
    JsonObject query = createQuery(user.principal().getString(options.getUsernameField()));
    return mongoClient.find(options.getCollectionName(), query)
      .compose(res -> {
        for (JsonObject jsonObject : res) {
          JsonArray roles = jsonObject.getJsonArray(options.getRoleField());
          if (roles != null) {
            for (int i = 0; i < roles.size(); i++) {
              String role = roles.getString(i);
              user.authorizations().add(providerId, RoleBasedAuthorization.create(role));
            }
          }
          JsonArray permissions = jsonObject.getJsonArray(options.getPermissionField());
          if (permissions != null) {
            for (int i = 0; i < permissions.size(); i++) {
              String permission = permissions.getString(i);
              user.authorizations().add(providerId, PermissionBasedAuthorization.create(permission));
            }
          }
        }
        return Future.succeededFuture();
      });
  }
}
