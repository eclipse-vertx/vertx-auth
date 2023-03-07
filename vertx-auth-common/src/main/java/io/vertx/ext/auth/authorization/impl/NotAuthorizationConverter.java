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

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.NotAuthorization;

import java.util.Objects;

import static io.vertx.ext.auth.authorization.impl.AuthorizationConverter.FIELD_AUTHORIZATIONS;
import static io.vertx.ext.auth.authorization.impl.AuthorizationConverter.FIELD_TYPE;

public class NotAuthorizationConverter {

  public final static String TYPE = "not";

  public static JsonObject encode(NotAuthorization value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject result = new JsonObject();
    result.put(FIELD_TYPE, TYPE);
    result.put(FIELD_AUTHORIZATIONS, AuthorizationConverter.encode(value.getAuthorization()));
    return result;
  }

  public static @Nullable NotAuthorization decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    return NotAuthorization.create(AuthorizationConverter.decode(json.getJsonObject(FIELD_AUTHORIZATIONS)));
  }

}
