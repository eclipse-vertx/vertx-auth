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

import java.util.Objects;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.impl.AuthorizationConverter;

public class UserConverter {

  private final static String FIELD_PRINCIPAL = "principal";
  private final static String FIELD_AUTHORIZATIONS = "authorizations";

  public static JsonObject encode(User value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject json = new JsonObject();
    json.put(FIELD_PRINCIPAL, value.principal());
    JsonObject jsonAuthorizations = new JsonObject();
    for (String providerId: value.authorizations().getProviderIds()) {
      JsonArray jsonAuthorizationByProvider = new JsonArray();
      jsonAuthorizations.put(providerId, jsonAuthorizationByProvider);
      for (Authorization authorization : value.authorizations().get(providerId)) {
        jsonAuthorizationByProvider.add(AuthorizationConverter.encode(authorization));
      }
    }
    json.put(FIELD_AUTHORIZATIONS, jsonAuthorizations);
    return json;
  }

  public static User decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    JsonObject principal = json.getJsonObject(FIELD_PRINCIPAL);
    User user = User.create(principal);
    // authorizations
    JsonObject jsonAuthorizations = json.getJsonObject(FIELD_AUTHORIZATIONS);
    for (String fieldName: jsonAuthorizations.fieldNames()) {
      JsonArray jsonAuthorizationByProvider = jsonAuthorizations.getJsonArray(fieldName);
      for (int i=0; i<jsonAuthorizationByProvider.size(); i++) {
        JsonObject jsonAuthorization = jsonAuthorizationByProvider.getJsonObject(i);
        user.authorizations().add(fieldName, AuthorizationConverter.decode(jsonAuthorization));
      }
    }
    return user;
  }

}
