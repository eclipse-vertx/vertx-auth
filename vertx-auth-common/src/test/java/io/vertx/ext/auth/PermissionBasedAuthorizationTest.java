package io.vertx.ext.auth;

import org.junit.Assert;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.impl.PermissionBasedAuthorizationConverter;
import io.vertx.test.core.VertxTestBase;

public class PermissionBasedAuthorizationTest extends VertxTestBase {

	@Test
	public void testConverter() {
		TestUtils.testJsonCodec(PermissionBasedAuthorization.create("p1"), PermissionBasedAuthorizationConverter.INSTANCE);
		TestUtils.testJsonCodec(PermissionBasedAuthorization.create("p1").setResource("resource"), PermissionBasedAuthorizationConverter.INSTANCE);
	}

	@Test
	public void testImplies1() {
		Assert.assertEquals(true, PermissionBasedAuthorization.create("p1").implies(PermissionBasedAuthorization.create("p1")));
	}

	@Test
	public void testImplies2() {
		Assert.assertEquals(true, PermissionBasedAuthorization.create("p1").setResource("r1").implies(PermissionBasedAuthorization.create("p1").setResource("r1")));
	}

	@Test
	public void testImplies3() {
		Assert.assertEquals(false, PermissionBasedAuthorization.create("p1").setResource("r1").implies(PermissionBasedAuthorization.create("p1")));
	}

	@Test
	public void testImplies4() {
		Assert.assertEquals(false, PermissionBasedAuthorization.create("p1").implies(PermissionBasedAuthorization.create("p1").setResource("r1")));
	}

	@Test
	public void testImplies5() {
		Assert.assertEquals(false, PermissionBasedAuthorization.create("p1").implies(PermissionBasedAuthorization.create("p2")));
	}

	@Test
	public void testMatch1() {
		vertx().createHttpServer().requestHandler(request -> {
			User user = User.create(new JsonObject().put("username", "dummy user"));
			user.authorizations().add(PermissionBasedAuthorization.create("p1").setResource("r1"));
			AuthorizationContext context = new AuthorizationContextImpl(user, request);
			assertEquals(true, PermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
			testComplete();
		})
		.listen(8080, "localhost");
		vertx().createHttpClient().getNow(8080,  "localhost", "/?variable1=r1");
		await();
	}

	@Test
	public void testMatch2() {
		vertx().createHttpServer().requestHandler(request -> {
			User user = User.create(new JsonObject().put("username", "dummy user"));
			user.authorizations().add(PermissionBasedAuthorization.create("p1").setResource("r1"));
			AuthorizationContext context = new AuthorizationContextImpl(user, request);
			assertEquals(false, PermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
			testComplete();
		})
		.listen(8080, "localhost");
		vertx().createHttpClient().getNow(8080,  "localhost", "/?variable1=r2");
		await();
	}

}
