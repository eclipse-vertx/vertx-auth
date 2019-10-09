package io.vertx.ext.auth;

import org.junit.Assert;
import org.junit.Test;

public class NotAuthorizationTest {

	@Test
	public void testImpliesOk1() {
		Assert.assertEquals(true, 
			NotAuthorization.create(PermissionBasedAuthorization.create("p1"))
			.implies(NotAuthorization.create(PermissionBasedAuthorization.create("p1")))
		);
	}

	@Test
	public void testImpliesKo1() {
		Assert.assertEquals(false, 
			NotAuthorization.create(PermissionBasedAuthorization.create("p1"))
			.implies(NotAuthorization.create(PermissionBasedAuthorization.create("p2")))
		);
	}

	@Test
	public void testImpliesKo2() {
		Assert.assertEquals(false, 
			NotAuthorization.create(PermissionBasedAuthorization.create("p1"))
			.implies(PermissionBasedAuthorization.create("p2"))
		);
	}

}
