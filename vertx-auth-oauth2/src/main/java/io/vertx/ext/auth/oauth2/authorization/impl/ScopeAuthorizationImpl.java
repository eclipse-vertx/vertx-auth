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

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;

import java.util.*;
import java.util.regex.Pattern;

public class ScopeAuthorizationImpl implements ScopeAuthorization {

  private static final JsonObject EMPTY = new JsonObject(Collections.emptyMap());

  private final String scopeSeparator;
  private final String claimKey;

  public ScopeAuthorizationImpl(String scopeSeparator, String claimKey) {
    this.scopeSeparator = Objects.requireNonNull(scopeSeparator);
    this.claimKey = claimKey;
  }

  @Override
  public String getId() {
    return "oauth2-scope";
  }

  @Override
  public Future<Void> getAuthorizations(User user) {
    String scopes =
      claimKey == null ?
        user.principal().getString("scope") :
        user.attributes().getJsonObject("accessToken", EMPTY).getString(claimKey);

    final Set<Authorization> authorizations;

    // avoid the case when scope is the literal "null" value.
    if (scopes != null) {
      authorizations = new HashSet<>();
      String sep = user.attributes().getString("scope_separator", scopeSeparator);
      for (String scope : scopes.split(Pattern.quote(sep))) {
        authorizations.add(PermissionBasedAuthorization.create(scope));
      }
    } else {
      authorizations = Collections.emptySet();
    }
    user.authorizations().put(getId(), authorizations);
    // return
    return Future.succeededFuture();
  }

  @Override
  public String separator() {
    return scopeSeparator;
  }

  @Override
  public String claimKey() {
    return claimKey;
  }

  @Override
  public String encode(List<String> scopes) {
    return String.join(separator(), scopes);
  }
}
