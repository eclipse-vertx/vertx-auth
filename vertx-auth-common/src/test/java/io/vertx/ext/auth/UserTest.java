/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth;

import io.vertx.ext.auth.authorization.*;
import org.junit.Assert;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.UserConverter;

public class UserTest {

  private void testReadWriteUser(User user1) {
    JsonObject jsonUser1 = UserConverter.encode(user1);
    User user2 = UserConverter.decode(jsonUser1);
    Assert.assertEquals(user1, user2);
  }

  public User createTestUser() {
    return User.create(new JsonObject().put("principal1", "value principal 1").put("principal2", "value principal 2"));
  }

  @Test
  public void testReadWriteUser1() {
    // only principal
    User user = createTestUser();
    testReadWriteUser(user);
  }

  @Test
  public void testReadWriteUser2() {
    // principal + authorizations
    User user = createTestUser();
    User.create(new JsonObject().put("name", "name1").put("value1", "a value"));
    user.authorizations().add("providerId", PermissionBasedAuthorization.create("permission1"));
    user.authorizations().add("providerId", RoleBasedAuthorization.create("role1"));
    user.authorizations().add("providerId", WildcardPermissionBasedAuthorization.create("orders:edit:1234"));
    user.authorizations().add("providerId", WildcardPermissionBasedAuthorization.create("billing:*"));
    user.authorizations().add("providerId", NotAuthorization.create(PermissionBasedAuthorization.create("permission1")));
    user.authorizations().add("providerId", AndAuthorization.create());
    user.authorizations()
        .add("providerId", AndAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("permission1"))
            .addAuthorization(RoleBasedAuthorization.create("role1"))
            .addAuthorization(PermissionBasedAuthorization.create("permission2"))
            .addAuthorization(RoleBasedAuthorization.create("role2")));
    user.authorizations().add("providerId", OrAuthorization.create());
    user.authorizations()
        .add("providerId", OrAuthorization.create().addAuthorization(PermissionBasedAuthorization.create("permission1"))
            .addAuthorization(RoleBasedAuthorization.create("role1"))
            .addAuthorization(PermissionBasedAuthorization.create("permission2"))
            .addAuthorization(RoleBasedAuthorization.create("role2")));
    testReadWriteUser(user);
  }

  @Test
  public void testReadWriteUser3() {
    // principal + authorizations + attributes
    User user = createTestUser();
    user.authorizations().add("providerId", RoleBasedAuthorization.create("role1"));
    user.authorizations().add("providerId", RoleBasedAuthorization.create("role2"));
    testReadWriteUser(user);
  }

  @Test
  public void testUniqueAuthorizations() {
    // principal + authorizations
    User user = createTestUser();
    user.authorizations().add("providerId", PermissionBasedAuthorization.create("permission1"));
    user.authorizations().add("providerId", PermissionBasedAuthorization.create("permission1"));
    user.authorizations().add("providerId", RoleBasedAuthorization.create("role1"));
    user.authorizations().add("providerId", RoleBasedAuthorization.create("role1"));
    Assert.assertEquals(2, user.authorizations().get("providerId").size());
  }

}
