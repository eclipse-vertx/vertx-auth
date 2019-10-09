package io.vertx.ext.auth;

import org.junit.Assert;
import org.junit.Test;

public class AndAuthorizationTest {

	@Test
	public void testImpliesOk1() {
		Assert.assertEquals(true, 
			AndAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(
				AndAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p1"))
			)
		);
	}

	@Test
	public void testImpliesOk2() {
		Assert.assertEquals(true, 
			AndAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(PermissionBasedAuthorization.create("p1")));
	}

	@Test
	public void testImpliesOk3() {
		Assert.assertEquals(true, 
			AndAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.addAuthorization(PermissionBasedAuthorization.create("p2"))
			.implies(
				AndAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p1"))
				.addAuthorization(PermissionBasedAuthorization.create("p2"))
			)
		);
	}

	@Test
	public void testImpliesOk4() {
		Assert.assertEquals(true, 
			AndAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.addAuthorization(PermissionBasedAuthorization.create("p2"))
			.implies(
				AndAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p1"))
			)
		);
	}

	@Test
	public void testImpliesOk5() {
		Assert.assertEquals(true, 
			AndAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.addAuthorization(PermissionBasedAuthorization.create("p2"))
			.implies(PermissionBasedAuthorization.create("p1")));
	}

	@Test
	public void testImpliesKo1() {
		Assert.assertEquals(false, 
			AndAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(
				AndAuthorization.create()
				.addAuthorization(PermissionBasedAuthorization.create("p2"))
			)
		);
	}

	@Test
	public void testImpliesKo2() {
		Assert.assertEquals(false, 
			AndAuthorization.create()
			.addAuthorization(PermissionBasedAuthorization.create("p1"))
			.implies(PermissionBasedAuthorization.create("p2")));
	}

}
