package io.vertx.ext.auth;

import org.junit.Assert;
import org.junit.Test;

public class AndAuthorizationTest {

  @Test
  public void testImpliesOk1() {
    Assert.assertEquals(true, AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
        .verify(AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))));
  }

  @Test
  public void testImpliesOk2() {
    Assert.assertEquals(true, AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
        .verify(PermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImpliesOk3() {
    Assert.assertEquals(true,
        AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
            .addAuthorization(PermissionBasedAuthorization.create("p2"))
            .verify(AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
                .addAuthorization(PermissionBasedAuthorization.create("p2"))));
  }

  @Test
  public void testImpliesOk4() {
    Assert.assertEquals(true,
        AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
            .addAuthorization(PermissionBasedAuthorization.create("p2"))
            .verify(AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))));
  }

  @Test
  public void testImpliesOk5() {
    Assert.assertEquals(true, AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
        .addAuthorization(PermissionBasedAuthorization.create("p2")).verify(PermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImpliesKo1() {
    Assert.assertEquals(false, AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
        .verify(AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p2"))));
  }

  @Test
  public void testImpliesKo2() {
    Assert.assertEquals(false, AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("p1"))
        .verify(PermissionBasedAuthorization.create("p2")));
  }

}
