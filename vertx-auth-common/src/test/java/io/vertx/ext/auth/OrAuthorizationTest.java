package io.vertx.ext.auth;

import org.junit.Assert;
import org.junit.Test;

public class OrAuthorizationTest {

	@Test
	public void testImpliesOk1() {
		Assert.assertEquals(true, 
			OrAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(
				OrAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p1"))
			)
		);
	}

	@Test
	public void testImpliesOk2() {
		Assert.assertEquals(true, 
			OrAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(PermissionBasedAuthorization.create("p1")));
	}

	@Test
	public void testImpliesOk3() {
		Assert.assertEquals(true, 
			OrAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.addAuthorization(PermissionBasedAuthorization.create("p2"))
			.implies(
				OrAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p1"))
				.addAuthorization(PermissionBasedAuthorization.create("p2"))
			)
		);
	}

	@Test
	public void testImpliesKo1() {
		Assert.assertEquals(false, 
			OrAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(
				OrAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p2"))
			)
		);
	}

	@Test
	public void testImpliesKo2() {
		Assert.assertEquals(false, 
			OrAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(PermissionBasedAuthorization.create("p2")));
	}

	@Test
	public void testImpliesKo3() {
		Assert.assertEquals(false, 
			OrAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.addAuthorization(PermissionBasedAuthorization.create("p2"))
			.implies(
				OrAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p1"))
			)
		);
	}

}
