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
package io.vertx.ext.auth.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.ChainAuth;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;

import java.util.ArrayList;
import java.util.List;

public class ChainAuthImpl implements ChainAuth {

  private final List<AuthenticationProvider> providers = new ArrayList<>();
  private final boolean all;

  public ChainAuthImpl(boolean all) {
    this.all = all;
  }

  @Override
  public ChainAuth add(AuthenticationProvider other) {
    providers.add(other);
    return this;
  }

  @Override
  public void authenticate(Credentials credentials, Handler<AsyncResult<User>> resultHandler) {
    try {
      credentials.checkValid(null);
      authenticate(credentials.toJson(), resultHandler);
    } catch (CredentialValidationException e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  @Override
  public void authenticate(final JsonObject authInfo, final Handler<AsyncResult<User>> resultHandler) {
    if (providers.size() == 0) {
      resultHandler.handle(Future.failedFuture("No providers in the auth chain."));
    } else {
      iterate(0, authInfo, resultHandler, null);
    }
  }

  private void iterate(final int idx, final JsonObject authInfo, final Handler<AsyncResult<User>> resultHandler, final User previousUser) {
    // stop condition
    if (idx >= providers.size()) {
      if (!all) {
        // no more providers, means that we failed to find a provider capable of performing this operation
        resultHandler.handle(Future.failedFuture("No more providers in the auth chain."));
      } else {
        // if ALL then a success completes
        resultHandler.handle(Future.succeededFuture(previousUser));
      }
      return;
    }

    // attempt to perform operation
    providers.get(idx).authenticate(authInfo, res -> {
      if (res.succeeded()) {
        if (!all) {
          // if ANY then a success completes
          resultHandler.handle(res);
        } else {
          // if ALL then a success check the next one
          User result = res.result();
          iterate(idx + 1, authInfo, resultHandler, previousUser == null ? result : previousUser.merge(result));
        }
      } else {
        // try again with next provider
        if (!all) {
          // try again with next provider
          iterate(idx + 1, authInfo, resultHandler, null);
        } else {
          // short circuit when ALL is used a failure is enough to terminate
          // no more providers, means that we failed to find a provider capable of performing this operation
          resultHandler.handle(res);
        }
      }
    });
  }
}
