package io.vertx.ext.auth;

import org.junit.Assert;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthorizationContextImpl;
import io.vertx.test.core.VertxTestBase;

public class RoleBasedAuthorizationTest extends VertxTestBase {

	@Test
	public void testConverter() {
		TestUtils.testJsonCodec(RoleBasedAuthorization.create("role1"), RoleBasedAuthorizationConverter::encode, RoleBasedAuthorizationConverter::decode);
		TestUtils.testJsonCodec(RoleBasedAuthorization.create("role1").setResource("resource"), RoleBasedAuthorizationConverter::encode, RoleBasedAuthorizationConverter::decode);
	}

	@Test
	public void testImplies1() {
		Assert.assertEquals(true, RoleBasedAuthorization.create("role1").implies(RoleBasedAuthorization.create("role1")));
	}

	@Test
	public void testImplies2() {
		Assert.assertEquals(true, RoleBasedAuthorization.create("p1").setResource("r1").implies(RoleBasedAuthorization.create("p1").setResource("r1")));
	}

	@Test
	public void testImplies3() {
		Assert.assertEquals(false, RoleBasedAuthorization.create("p1").setResource("r1").implies(RoleBasedAuthorization.create("p1")));
	}

	@Test
	public void testImplies4() {
		Assert.assertEquals(false, RoleBasedAuthorization.create("p1").implies(RoleBasedAuthorization.create("p1").setResource("r1")));
	}

	@Test
	public void testImplies5() {
		Assert.assertEquals(false, RoleBasedAuthorization.create("role1").implies(RoleBasedAuthorization.create("role2")));
	}

	@Test
	public void testMatch1() {
		vertx().createHttpServer().requestHandler(request -> {
			User user = User.create(new JsonObject().put("username", "dummy user"));
			user.authorizations().add(RoleBasedAuthorization.create("p1").setResource("r1"));
			AuthorizationContext context = new AuthorizationContextImpl(user, request);
			assertEquals(true, RoleBasedAuthorization.create("p1").setResource("{variable1}").match(context));
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
			user.authorizations().add(RoleBasedAuthorization.create("p1").setResource("r1"));
			AuthorizationContext context = new AuthorizationContextImpl(user, request);
			assertEquals(false, RoleBasedAuthorization.create("p1").setResource("{variable1}").match(context));
			testComplete();
		})
		.listen(8080, "localhost");
		vertx().createHttpClient().getNow(8080,  "localhost", "/?variable1=r2");
		await();
	}

}
