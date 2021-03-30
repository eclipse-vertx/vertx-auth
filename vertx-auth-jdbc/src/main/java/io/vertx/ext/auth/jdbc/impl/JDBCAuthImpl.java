/*
 * Copyright 2014 Red Hat, Inc.
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

package io.vertx.ext.auth.jdbc.impl;

import java.util.Objects;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.auth.jdbc.JDBCAuthentication;
import io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions;
import io.vertx.ext.auth.jdbc.JDBCAuthorization;
import io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthImpl implements AuthProvider, JDBCAuth {

  private JDBCClient client;
  private JDBCAuthentication authenticationProvider;
  private JDBCAuthenticationOptions authenticationOptions;
  private JDBCAuthorization authorizationProvider;
  private JDBCAuthorizationOptions authorizationOptions;
  private JDBCHashStrategy hashStrategy;

  public JDBCAuthImpl(Vertx vertx, JDBCClient client) {
    this.client = client;
    this.hashStrategy = JDBCHashStrategy.createSHA512(vertx);
    this.authenticationOptions = new JDBCAuthenticationOptions();
    this.authorizationOptions = new JDBCAuthorizationOptions();
    this.authenticationProvider = JDBCAuthentication.create(client, hashStrategy, authenticationOptions);
    this.authorizationProvider = JDBCAuthorization.create("jdbc-auth", client, authorizationOptions);
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    authenticate(new UsernamePasswordCredentials(authInfo), resultHandler);
  }

  @Override
  public void authenticate(Credentials credentials, Handler<AsyncResult<User>> resultHandler) {
    try {
      UsernamePasswordCredentials authInfo = (UsernamePasswordCredentials) credentials;
      authInfo.checkValid(null);

      authenticationProvider.authenticate(credentials, authenticationResult -> {
        if (authenticationResult.failed()) {
          resultHandler.handle(Future.failedFuture(authenticationResult.cause()));
        } else {
          User user = authenticationResult.result();
          authorizationProvider.getAuthorizations(user, userAuthorizationResult -> {
            if (userAuthorizationResult.failed()) {
              // what do we do in case something goes wrong during authorizationProvider but we've got a correct user ?
              // for now, lets return a faillure
              resultHandler.handle(Future.failedFuture(userAuthorizationResult.cause()));
            }
            else {
              resultHandler.handle(Future.succeededFuture(user));
            }
          });
        }
      });
    } catch (RuntimeException e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  @Override
  public JDBCAuth setAuthenticationQuery(String authenticationQuery) {
    this.authenticationOptions.setAuthenticationQuery(authenticationQuery);
    return this;
  }

  @Override
  public JDBCAuth setRolesQuery(String rolesQuery) {
    this.authorizationOptions.setRolesQuery(rolesQuery);
    return this;
  }

  @Override
  public JDBCAuth setPermissionsQuery(String permissionsQuery) {
    this.authorizationOptions.setPermissionsQuery(permissionsQuery);
    return this;
  }

  @Override
  public JDBCAuth setRolePrefix(String rolePrefix) {
    return this;
  }

  @Override
  public JDBCAuth setHashStrategy(JDBCHashStrategy strategy) {
    this.hashStrategy = Objects.requireNonNull(strategy);
    // we've got to recreate the authenticationProvider provider to pick-up the new hash strategy
    this.authenticationProvider = JDBCAuthentication.create(client, strategy, authenticationOptions);
    return this;
  }

  @Override
  public String computeHash(String password, String salt, int version) {
    return hashStrategy.computeHash(password, salt, version);
  }

  @Override
  public String generateSalt() {
    return hashStrategy.generateSalt();
  }

  @Override
  public JDBCAuth setNonces(JsonArray nonces) {
    hashStrategy.setNonces(nonces);
    return this;
  }

  String getRolesQuery() {
    return authorizationOptions.getRolesQuery();
  }

  String getPermissionsQuery() {
    return authorizationOptions.getPermissionsQuery();
  }
}
