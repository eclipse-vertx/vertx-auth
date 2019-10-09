package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.json.JsonObject;
import io.vertx.core.spi.json.JsonCodec;
import io.vertx.ext.auth.NotAuthorization;

public class NotAuthorizationConverter implements JsonCodec<NotAuthorization, JsonObject> {

	public final static NotAuthorizationConverter INSTANCE = new NotAuthorizationConverter();

	private final static String FIELD_TYPE = "type";
	private final static String TYPE_NOT_AUTHORIZATION = "not";
	private final static String FIELD_AUTHORIZATION = "authorization";

	// private constructor
	private NotAuthorizationConverter() {
	}
	
	@Override
	public JsonObject encode(NotAuthorization value) throws IllegalArgumentException {
		Objects.requireNonNull(value);
		
		JsonObject result = new JsonObject();
		result.put(FIELD_TYPE, TYPE_NOT_AUTHORIZATION);
		result.put(FIELD_AUTHORIZATION, AuthorizationConverter.INSTANCE.encode(value.getAuthorization()));
		return result;
	}

	@Override
	public Class<NotAuthorization> getTargetClass() {
		return NotAuthorization.class;
	}

	@Override
	public NotAuthorization decode(JsonObject json) throws IllegalArgumentException {
		Objects.requireNonNull(json);

		if (TYPE_NOT_AUTHORIZATION.equals(json.getString(FIELD_TYPE))) {
			return NotAuthorization.create(AuthorizationConverter.INSTANCE.decode(json.getJsonObject(FIELD_AUTHORIZATION)));
		}
		return null;
	}

}
