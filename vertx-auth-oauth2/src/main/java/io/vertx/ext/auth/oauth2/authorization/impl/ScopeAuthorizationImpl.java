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
package io.vertx.ext.auth.oauth2.authorization.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class ScopeAuthorizationImpl implements ScopeAuthorization {

  private final String scopeSeparator;

  public ScopeAuthorizationImpl(String scopeSeparator) {
    this.scopeSeparator = scopeSeparator;
  }

  @Override
  public String getId() {
    return "oauth2-scope";
  }

  @Override
  public void getAuthorizations(User user, Handler<AsyncResult<Set<Authorization>>> handler) {
    String scopes = user.principal().getString("scope");

    final Set<Authorization> authorizations = new HashSet<>();

    // avoid the case when scope is the literal "null" value.
    if (scopes != null) {
      String sep = user.attributes().getString("scope_separator", scopeSeparator);
      for (String scope : scopes.split(Pattern.quote(sep))) {
        authorizations.add(PermissionBasedAuthorization.create(scope));
      }
    }
    // return
    handler.handle(Future.succeededFuture(authorizations));
  }

  @Override
  public String separator() {
    return scopeSeparator;
  }

  @Override
  public String encode(List<String> scopes) {
    return String.join(separator(), scopes);
  }
}
