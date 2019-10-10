package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AndAuthorization;
import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.NotAuthorization;
import io.vertx.ext.auth.OrAuthorization;
import io.vertx.ext.auth.PermissionBasedAuthorization;
import io.vertx.ext.auth.RoleBasedAuthorization;
import io.vertx.ext.auth.WildcardPermissionBasedAuthorization;

public class AuthorizationConverter {

  public final static Authorization decode(JsonObject json) throws IllegalArgumentException {
    Objects.requireNonNull(json);

    Authorization result = AndAuthorizationConverter.decode(json);
    if (result == null) {
      result = NotAuthorizationConverter.decode(json);
      if (result == null) {
        result = OrAuthorizationConverter.decode(json);
        if (result == null) {
          result = PermissionBasedAuthorizationConverter.decode(json);
          if (result == null) {
            result = RoleBasedAuthorizationConverter.decode(json);
            if (result == null) {
              result = WildcardPermissionBasedAuthorizationConverter.decode(json);
            }
          }
        }
      }
    }
    return result;
  }

  public final static JsonObject encode(Authorization value) throws IllegalArgumentException {
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
