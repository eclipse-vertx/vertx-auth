package io.vertx.ext.auth;

import org.junit.Assert;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthorizationContextImpl;
import io.vertx.test.core.VertxTestBase;

public class WildcardPermissionBasedAuthorizationTest extends VertxTestBase {

	@Test
	public void testConverter() {
		TestUtils.testJsonCodec(WildcardPermissionBasedAuthorization.create("wp1"), WildcardPermissionBasedAuthorizationConverter::encode, WildcardPermissionBasedAuthorizationConverter::decode);
		TestUtils.testJsonCodec(WildcardPermissionBasedAuthorization.create("wp1").setResource("resource"), WildcardPermissionBasedAuthorizationConverter::encode, WildcardPermissionBasedAuthorizationConverter::decode);
	}

	@Test
	public void testImplies1() {
		Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("wp1").implies(WildcardPermissionBasedAuthorization.create("wp1")));
	}

	@Test
	public void testImplies2() {
		Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("*").implies(WildcardPermissionBasedAuthorization.create("wp1")));
	}

	@Test
	public void testImplies3() {
		Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("printer:*").implies(WildcardPermissionBasedAuthorization.create("printer:read")));
	}

	@Test
	public void testImplies4() {
		Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("*:read").implies(WildcardPermissionBasedAuthorization.create("printer:read")));
	}

	@Test
	public void testImplies5() {
		Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("p1").implies(WildcardPermissionBasedAuthorization.create("p1").setResource("r1")));
	}

	@Test
	public void testImplies6() {
		Assert.assertEquals(false, WildcardPermissionBasedAuthorization.create("p1").setResource("r1").implies(WildcardPermissionBasedAuthorization.create("p1")));
	}

	@Test
	public void testImplies7() {
		Assert.assertEquals(false, WildcardPermissionBasedAuthorization.create("wp1").implies(WildcardPermissionBasedAuthorization.create("wp2")));
	}

	@Test
	public void testImplies8() {
		Assert.assertEquals(false, WildcardPermissionBasedAuthorization.create("printer:read").implies(WildcardPermissionBasedAuthorization.create("*")));
	}

	@Test
	public void testImplies9() {
		Assert.assertEquals(false, WildcardPermissionBasedAuthorization.create("*:read").implies(WildcardPermissionBasedAuthorization.create("printer:edit")));
	}

	@Test
	public void testMatch1() {
		vertx().createHttpServer().requestHandler(request -> {
			User user = User.create(new JsonObject().put("username", "dummy user"));
			user.authorizations().add(WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
			AuthorizationContext context = new AuthorizationContextImpl(user, request);
			assertEquals(true, WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
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
			user.authorizations().add(WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
			AuthorizationContext context = new AuthorizationContextImpl(user, request);
			assertEquals(false, WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
			testComplete();
		})
		.listen(8080, "localhost");
		vertx().createHttpClient().getNow(8080,  "localhost", "/?variable1=r2");
		await();
	}

}
