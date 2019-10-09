package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.json.JsonObject;
import io.vertx.core.spi.json.JsonCodec;
import io.vertx.ext.auth.AndAuthorization;
import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.NotAuthorization;
import io.vertx.ext.auth.OrAuthorization;
import io.vertx.ext.auth.PermissionBasedAuthorization;
import io.vertx.ext.auth.RoleBasedAuthorization;
import io.vertx.ext.auth.WildcardPermissionBasedAuthorization;

public class AuthorizationConverter implements JsonCodec<Authorization, JsonObject> {

	public final static AuthorizationConverter INSTANCE = new AuthorizationConverter();
	
	private AuthorizationConverter() {
	}

	@Override
	public Authorization decode(JsonObject json) throws IllegalArgumentException {
		Objects.requireNonNull(json);
		
		Authorization result = AndAuthorizationConverter.INSTANCE.decode(json);
		if (result==null) {
			result = NotAuthorizationConverter.INSTANCE.decode(json);
			if (result==null) {
				result = OrAuthorizationConverter.INSTANCE.decode(json);
				if (result==null) {
					result = PermissionBasedAuthorizationConverter.INSTANCE.decode(json);
					if (result==null) {
						result = RoleBasedAuthorizationConverter.INSTANCE.decode(json);
						if (result==null) {
							result = WildcardPermissionBasedAuthorizationConverter.INSTANCE.decode(json);
						}
					}
				}
			}
		}
		return result;
	}

	@Override
	public JsonObject encode(Authorization value) throws IllegalArgumentException {
		Objects.requireNonNull(value);

		// decide which JsonCodec we should use
		if (value instanceof AndAuthorization) {
			return AndAuthorizationConverter.INSTANCE.encode((AndAuthorization) value);
		}
		else if (value instanceof NotAuthorization) {
			return NotAuthorizationConverter.INSTANCE.encode((NotAuthorization) value);
		}
		else if (value instanceof OrAuthorization) {
			return OrAuthorizationConverter.INSTANCE.encode((OrAuthorization) value);
		}
		else if (value instanceof PermissionBasedAuthorization) {
			return PermissionBasedAuthorizationConverter.INSTANCE.encode((PermissionBasedAuthorization) value);
		}
		else if (value instanceof RoleBasedAuthorization) {
			return RoleBasedAuthorizationConverter.INSTANCE.encode((RoleBasedAuthorization) value);
		}
		else if (value instanceof WildcardPermissionBasedAuthorization) {
			return WildcardPermissionBasedAuthorizationConverter.INSTANCE.encode((WildcardPermissionBasedAuthorization) value);
		}
		else {
			throw new IllegalArgumentException("Unsupported authorization " + value.getClass());
		}
	}

	@Override
	public Class<Authorization> getTargetClass() {
		return Authorization.class;
	}

}
