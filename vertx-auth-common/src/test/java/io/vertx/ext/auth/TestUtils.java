package io.vertx.ext.auth;

import org.junit.Assert;

import io.vertx.core.json.JsonObject;
import io.vertx.core.spi.json.JsonCodec;

public class TestUtils {

	public final static <T> void testJsonCodec(T authorization, JsonCodec<T, JsonObject> codec) {
		Assert.assertNotNull(authorization);
		JsonObject json = codec.encode(authorization);
		T otherAuthorization = codec.decode(json);
		Assert.assertEquals(authorization, otherAuthorization);
	}

	public final static AuthorizationContext getTestAuthorizationContext() {
		return getTestAuthorizationContext(User.create(new JsonObject().put("username", "dummy user")));
	}

	public final static AuthorizationContext getTestAuthorizationContext(User user) {
		return null;
	}

}
