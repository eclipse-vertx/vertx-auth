package io.vertx.ext.auth;

import java.util.function.Function;

import org.junit.Assert;

import io.vertx.core.json.JsonObject;

public class TestUtils {

	public final static <T> void testJsonCodec(T authorization, Function<T, JsonObject> toJsonConverter, Function<JsonObject, T> fromJsonConverter) {
		Assert.assertNotNull(authorization);
		JsonObject json = toJsonConverter.apply(authorization);
		T otherAuthorization = fromJsonConverter.apply(json);
		Assert.assertEquals(authorization, otherAuthorization);
	}

	public final static AuthorizationContext getTestAuthorizationContext() {
		return getTestAuthorizationContext(User.create(new JsonObject().put("username", "dummy user")));
	}

	public final static AuthorizationContext getTestAuthorizationContext(User user) {
		return null;
	}

}
