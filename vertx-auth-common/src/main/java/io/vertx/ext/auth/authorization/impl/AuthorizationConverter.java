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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.AndAuthorization;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.NotAuthorization;
import io.vertx.ext.auth.authorization.OrAuthorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.authorization.WildcardPermissionBasedAuthorization;

public class AuthorizationConverter {

  public final static String FIELD_TYPE = "type";
  public final static String FIELD_AUTHORIZATIONS = "authorizations";

  public static Authorization decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    switch (Objects.requireNonNull(json.getString(FIELD_TYPE))) {
      case AndAuthorizationConverter.TYPE:
        return AndAuthorizationConverter.decode(json);
      case NotAuthorizationConverter.TYPE:
        return NotAuthorizationConverter.decode(json);
      case OrAuthorizationConverter.TYPE:
        return OrAuthorizationConverter.decode(json);
      case PermissionBasedAuthorizationConverter.TYPE:
        return PermissionBasedAuthorizationConverter.decode(json);
      case RoleBasedAuthorizationConverter.TYPE:
        return RoleBasedAuthorizationConverter.decode(json);
      case WildcardPermissionBasedAuthorizationConverter.TYPE:
        return WildcardPermissionBasedAuthorizationConverter.decode(json);
      default:
        throw new IllegalArgumentException("Unsupported authorization " + json.getString(FIELD_TYPE));
    }
  }

  public static JsonObject encode(Authorization value) throws IllegalArgumentException {
    Objects.requireNonNull(value);

    // decide which JsonCodec we should use
    if (value instanceof AndAuthorization) {
      return AndAuthorizationConverter.encode((AndAuthorization) value);
    } else if (value instanceof NotAuthorization) {
      return NotAuthorizationConverter.encode((NotAuthorization) value);
    } else if (value instanceof OrAuthorization) {
      return OrAuthorizationConverter.encode((OrAuthorization) value);
    } else if (value instanceof PermissionBasedAuthorization) {
      return PermissionBasedAuthorizationConverter.encode((PermissionBasedAuthorization) value);
    } else if (value instanceof RoleBasedAuthorization) {
      return RoleBasedAuthorizationConverter.encode((RoleBasedAuthorization) value);
    } else if (value instanceof WildcardPermissionBasedAuthorization) {
      return WildcardPermissionBasedAuthorizationConverter.encode((WildcardPermissionBasedAuthorization) value);
    } else {
      throw new IllegalArgumentException("Unsupported authorization " + value.getClass());
    }
  }

}
