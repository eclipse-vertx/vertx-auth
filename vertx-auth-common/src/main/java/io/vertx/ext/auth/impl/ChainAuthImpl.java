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
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.ChainAuth;
import io.vertx.ext.auth.User;

import java.util.ArrayList;
import java.util.List;

public class ChainAuthImpl implements ChainAuth {

  private final List<AuthProvider> providers = new ArrayList<>();

  @Override
  public ChainAuth append(AuthProvider other) {
    providers.add(other);
    return this;
  }

  @Override
  public boolean remove(AuthProvider other) {
    return providers.remove(other);
  }

  @Override
  public void clear() {
    providers.clear();
  }

  @Override
  public void authenticate(final JsonObject authInfo, final Handler<AsyncResult<User>> resultHandler) {
    new Handler<Integer>() {
      @Override
      public void handle(final Integer i) {
        final Handler<Integer> self = this;

        // stop condition
        if (i == providers.size()) {
          // no more providers, means that we failed to find a provider capable of performing this operation
          resultHandler.handle(Future.failedFuture("No more providers"));
          return;
        }

        // attempt to perform operation
        providers.get(i).authenticate(authInfo, res -> {
          if (res.succeeded()) {
            resultHandler.handle(res);
          } else {
            // try again with next provider
            self.handle(i + 1);
          }
        });
      }
    }
    // start the iterator
    .handle(0);
  }
}
