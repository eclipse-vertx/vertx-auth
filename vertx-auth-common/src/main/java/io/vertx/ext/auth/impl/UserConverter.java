/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.Authorizations;
import io.vertx.ext.auth.authorization.impl.AuthorizationConverter;

import java.util.*;

public class UserConverter {

  private final static String FIELD_PRINCIPAL = "principal";
  private final static String FIELD_AUTHORIZATIONS = "authorizations";
  private final static String FIELD_ATTRIBUTES = "attributes";

  public static JsonObject encode(User value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject json = new JsonObject();
    json.put(FIELD_PRINCIPAL, value.principal());
    Authorizations authorizations = value.authorizations();
    if (authorizations != null && !authorizations.isEmpty()) {
      JsonObject jsonAuthorizations = new JsonObject();
      authorizations
        .forEach((providerId, authorization) -> {
          final JsonArray jsonAuthorizationByProvider;
          if (jsonAuthorizations.containsKey(providerId)) {
            jsonAuthorizationByProvider = jsonAuthorizations.getJsonArray(providerId);
          } else {
            jsonAuthorizationByProvider = new JsonArray();
            jsonAuthorizations.put(providerId, jsonAuthorizationByProvider);
          }
          jsonAuthorizationByProvider.add(AuthorizationConverter.encode(authorization));
        });
      json.put(FIELD_AUTHORIZATIONS, jsonAuthorizations);
    }
    json.put(FIELD_ATTRIBUTES, value.attributes());
    return json;
  }

  public static User decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    JsonObject principal = json.getJsonObject(FIELD_PRINCIPAL);
    User user = User.create(principal);
    // authorizations
    JsonObject jsonAuthorizations = json.getJsonObject(FIELD_AUTHORIZATIONS);
    final Map<String, Set<Authorization>> decodedAuthorizations;
    if (jsonAuthorizations != null) {
      decodedAuthorizations = new HashMap<>(jsonAuthorizations.size());
      for (String fieldName : jsonAuthorizations.fieldNames()) {
        JsonArray jsonAuthorizationByProvider = jsonAuthorizations.getJsonArray(fieldName);
        final Set<Authorization> authorizations;
        if (jsonAuthorizationByProvider == null) {
          authorizations = Collections.emptySet();
        } else {
          authorizations = new HashSet<>(jsonAuthorizationByProvider.size());
          for (int i = 0; i < jsonAuthorizationByProvider.size(); i++) {
            authorizations.add(AuthorizationConverter.decode(jsonAuthorizationByProvider.getJsonObject(i)));
          }
        }
        decodedAuthorizations.put(fieldName, authorizations);
      }
      user.authorizations()
        .putAll(decodedAuthorizations);
    }

    user.attributes()
      .mergeIn(json.getJsonObject(FIELD_ATTRIBUTES, new JsonObject()));

    return user;
  }

}
