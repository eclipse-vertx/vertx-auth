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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.WildcardPermissionBasedAuthorization;

public class WildcardPermissionBasedAuthorizationConverter {

  private final static String FIELD_TYPE = "type";
  private final static String TYPE_WILDCARD_PERMISSION = "wildcard";
  private final static String FIELD_PERMISSION = "permission";
  private final static String FIELD_RESOURCE = "resource";

  public static JsonObject encode(WildcardPermissionBasedAuthorization value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    JsonObject result = new JsonObject();
    result.put(FIELD_TYPE, TYPE_WILDCARD_PERMISSION);
    result.put(FIELD_PERMISSION, value.getPermission());
    if (value.getResource() != null) {
      result.put(FIELD_RESOURCE, value.getResource());
    }
    return result;
  }

  public static @Nullable WildcardPermissionBasedAuthorization decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    if (TYPE_WILDCARD_PERMISSION.equals(json.getString(FIELD_TYPE))) {
      WildcardPermissionBasedAuthorization result = WildcardPermissionBasedAuthorization
          .create(json.getString(FIELD_PERMISSION));
      if (json.getString(FIELD_RESOURCE) != null) {
        result.setResource(json.getString(FIELD_RESOURCE));
      }
      return result;
    }
    return null;
  }

}
