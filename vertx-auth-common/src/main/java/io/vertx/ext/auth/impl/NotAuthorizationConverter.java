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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.NotAuthorization;

public class NotAuthorizationConverter {

  private final static String FIELD_TYPE = "type";
  private final static String TYPE_NOT_AUTHORIZATION = "not";
  private final static String FIELD_AUTHORIZATION = "authorization";

  public final static JsonObject encode(NotAuthorization value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject result = new JsonObject();
    result.put(FIELD_TYPE, TYPE_NOT_AUTHORIZATION);
    result.put(FIELD_AUTHORIZATION, AuthorizationConverter.encode(value.getAuthorization()));
    return result;
  }

  public final static NotAuthorization decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    if (TYPE_NOT_AUTHORIZATION.equals(json.getString(FIELD_TYPE))) {
      return NotAuthorization.create(AuthorizationConverter.decode(json.getJsonObject(FIELD_AUTHORIZATION)));
    }
    return null;
  }

}
