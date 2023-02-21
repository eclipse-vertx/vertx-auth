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
package io.vertx.ext.auth.authorization.impl;

import java.util.Objects;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.OrAuthorization;

import static io.vertx.ext.auth.authorization.impl.AuthorizationConverter.FIELD_AUTHORIZATIONS;
import static io.vertx.ext.auth.authorization.impl.AuthorizationConverter.FIELD_TYPE;

public class OrAuthorizationConverter {

  public final static String TYPE = "or";

  public static JsonObject encode(OrAuthorization value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject result = new JsonObject();
    result.put(FIELD_TYPE, TYPE);
    JsonArray authorizations = new JsonArray();
    result.put(FIELD_AUTHORIZATIONS, authorizations);
    for (Authorization authorization : value.getAuthorizations()) {
      authorizations.add(AuthorizationConverter.encode(authorization));
    }
    return result;
  }

  public static @Nullable OrAuthorization decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    OrAuthorization result = OrAuthorization.create();
    JsonArray authorizations = json.getJsonArray(FIELD_AUTHORIZATIONS);
    for (int i = 0; i < authorizations.size(); i++) {
      JsonObject authorization = authorizations.getJsonObject(i);
      result.addAuthorization(AuthorizationConverter.decode(authorization));
    }
    return result;
  }
}
