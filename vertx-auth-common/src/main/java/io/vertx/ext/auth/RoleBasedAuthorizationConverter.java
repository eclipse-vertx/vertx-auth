package io.vertx.ext.auth;

import java.util.Objects;

import io.vertx.core.json.JsonObject;

public class RoleBasedAuthorizationConverter {

	private final static String FIELD_TYPE = "type";
	private final static String TYPE_ROLE_BASED_AUTHORIZATION = "role";
	private final static String FIELD_ROLE = "role";
	private final static String FIELD_RESOURCE = "resource";

	public final static JsonObject encode(RoleBasedAuthorization value) throws IllegalArgumentException {
		Objects.requireNonNull(value);
		
		JsonObject result = new JsonObject();
		result.put(FIELD_TYPE, TYPE_ROLE_BASED_AUTHORIZATION);
		result.put(FIELD_ROLE, value.getRole());
		if (value.getResource()!=null) {
			result.put(FIELD_RESOURCE, value.getResource());
		}
		return result;
	}

	public final static RoleBasedAuthorization decode(JsonObject json) throws IllegalArgumentException {
		Objects.requireNonNull(json);

		if (TYPE_ROLE_BASED_AUTHORIZATION.equals(json.getString(FIELD_TYPE))) {
			RoleBasedAuthorization result = RoleBasedAuthorization.create(json.getString(FIELD_ROLE));
			if (json.getString(FIELD_RESOURCE)!=null) {
				result.setResource(json.getString(FIELD_RESOURCE));
			}
			return result;

		}
		return null;
	}

}
