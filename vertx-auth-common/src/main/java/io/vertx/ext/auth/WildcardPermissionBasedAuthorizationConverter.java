package io.vertx.ext.auth;

import java.util.Objects;

import io.vertx.core.json.JsonObject;

public class WildcardPermissionBasedAuthorizationConverter {

	private final static String FIELD_TYPE = "type";
	private final static String TYPE_WILDCARD_PERMISSION = "wildcard";
	private final static String FIELD_PERMISSION = "permission";
	private final static String FIELD_RESOURCE = "resource";

	public final static JsonObject encode(WildcardPermissionBasedAuthorization value) throws IllegalArgumentException {
		Objects.requireNonNull(value);
		
		JsonObject result = new JsonObject();
		result.put(FIELD_TYPE, TYPE_WILDCARD_PERMISSION);
		result.put(FIELD_PERMISSION, value.getPermission());
		if (value.getResource()!=null) {
			result.put(FIELD_RESOURCE, value.getResource());
		}
		return result;
	}

	public final static WildcardPermissionBasedAuthorization decode(JsonObject json) throws IllegalArgumentException {
		Objects.requireNonNull(json);

		if (TYPE_WILDCARD_PERMISSION.equals(json.getString(FIELD_TYPE))) {
			WildcardPermissionBasedAuthorization result = WildcardPermissionBasedAuthorization.create(json.getString(FIELD_PERMISSION));
			if (json.getString(FIELD_RESOURCE)!=null) {
				result.setResource(json.getString(FIELD_RESOURCE));
			}
			return result;
		}
		return null;
	}

}
