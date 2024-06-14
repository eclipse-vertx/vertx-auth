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

import io.vertx.core.Future;
import io.vertx.ext.auth.chain.ChainAuth;
import io.vertx.ext.auth.user.User;
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
  public Future<User> authenticate(Credentials credentials) {
    try {
      credentials.checkValid(null);
    } catch (CredentialValidationException e) {
      return Future.failedFuture(e);
    }

    if (providers.size() == 0) {
      return Future.failedFuture("No providers in the auth chain.");
    } else {
      return iterate(0, credentials, null);
    }
  }

  private Future<User> iterate(final int idx, final Credentials credentials, final User previousUser) {
    // stop condition
    if (idx >= providers.size()) {
      if (!all) {
        // no more providers, means that we failed to find a provider capable of performing this operation
        return Future.failedFuture("No more providers in the auth chain.");
      } else {
        // if ALL then a success completes
        return Future.succeededFuture(previousUser);
      }
    }

    // attempt to perform operation
    return providers.get(idx)
      .authenticate(credentials)
      .compose(user -> {
        if (!all) {
          // if ANY then a success completes
          return Future.succeededFuture(user);
        } else {
          // if ALL then a success check the next one
          return iterate(idx + 1, credentials, previousUser == null ? user : previousUser.merge(user));
        }
      })
      .recover(err -> {
        // try again with next provider
        if (!all) {
          // try again with next provider
          return iterate(idx + 1, credentials, null);
        } else {
          // short circuit when ALL is used a failure is enough to terminate
          // no more providers, means that we failed to find a provider capable of performing this operation
          return Future.failedFuture(err);
        }
      });
  }
}
