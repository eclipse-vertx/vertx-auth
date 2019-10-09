package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.json.JsonObject;
import io.vertx.core.spi.json.JsonCodec;
import io.vertx.ext.auth.RoleBasedAuthorization;

public class RoleBasedAuthorizationConverter implements JsonCodec<RoleBasedAuthorization, JsonObject> {

	public final static RoleBasedAuthorizationConverter INSTANCE = new RoleBasedAuthorizationConverter();

	private final static String FIELD_TYPE = "type";
	private final static String TYPE_ROLE_BASED_AUTHORIZATION = "role";
	private final static String FIELD_ROLE = "role";
	private final static String FIELD_RESOURCE = "resource";

	// private constructor
	private RoleBasedAuthorizationConverter() {
	}
	
	@Override
	public JsonObject encode(RoleBasedAuthorization value) throws IllegalArgumentException {
		Objects.requireNonNull(value);
		
		JsonObject result = new JsonObject();
		result.put(FIELD_TYPE, TYPE_ROLE_BASED_AUTHORIZATION);
		result.put(FIELD_ROLE, value.getRole());
		if (value.getResource()!=null) {
			result.put(FIELD_RESOURCE, value.getResource());
		}
		return result;
	}

	@Override
	public Class<RoleBasedAuthorization> getTargetClass() {
		return RoleBasedAuthorization.class;
	}

	@Override
	public RoleBasedAuthorization decode(JsonObject json) throws IllegalArgumentException {
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
