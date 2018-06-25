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
package io.vertx.ext.auth.oauth2.impl.flow;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.impl.OAuth2TokenImpl;

/**
 * @author Paulo Lopes
 */
public class PasswordImpl extends AbstractOAuth2Flow implements OAuth2Flow {

  private final OAuth2AuthProviderImpl provider;

  public PasswordImpl(OAuth2AuthProviderImpl provider) {
    super(provider.getVertx(), provider.getConfig());
    this.provider = provider;
  }

  /**
   * Returns the Access Token object.
   *
   * @param params - username: A string that represents the registered username.
   *                 password: A string that represents the registered password.
   *                 scope:    A String that represents the application privileges.
   * @param handler - The handler function returning the results.
   */
  @Override
  public void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler) {
    getToken("password", params, res -> {
      if (res.failed()) {
        handler.handle(Future.failedFuture(res.cause()));
        return;
      }

      AccessToken token;

      try {
        token = new OAuth2TokenImpl(provider, res.result());
      } catch (RuntimeException e) {
        handler.handle(Future.failedFuture(e));
        return;
      }

      handler.handle(Future.succeededFuture(token));
    });
  }
}
