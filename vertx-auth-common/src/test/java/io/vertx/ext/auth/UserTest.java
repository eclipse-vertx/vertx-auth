package io.vertx.ext.auth;

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
    User user = createTestUser();User.create(new JsonObject().put("name", "name1").put("value1", "a value"));
    user.authorizations().add(PermissionBasedAuthorization.create("permission1"));
    user.authorizations().add(RoleBasedAuthorization.create("role1"));
    user.authorizations().add(WildcardPermissionBasedAuthorization.create("orders:edit:1234"));
    user.authorizations().add(WildcardPermissionBasedAuthorization.create("billing:*"));
    user.authorizations().add(NotAuthorization.create(PermissionBasedAuthorization.create("permission1")));
    user.authorizations().add(AndAuthorization.create());
    user.authorizations().add(
    	AndAuthorization.create()
   		.addAuthorization(PermissionBasedAuthorization.create("permission1"))
   		.addAuthorization(RoleBasedAuthorization.create("role1"))
   		.addAuthorization(PermissionBasedAuthorization.create("permission2"))
   		.addAuthorization(RoleBasedAuthorization.create("role2"))
    );
    user.authorizations().add(OrAuthorization.create());
    user.authorizations().add(
        	OrAuthorization.create()
       		.addAuthorization(PermissionBasedAuthorization.create("permission1"))
       		.addAuthorization(RoleBasedAuthorization.create("role1"))
       		.addAuthorization(PermissionBasedAuthorization.create("permission2"))
       		.addAuthorization(RoleBasedAuthorization.create("role2"))
        );
    testReadWriteUser(user);
  }

  @Test
  public void testReadWriteUser3() {
    // principal + authorizations + attributes
    User user = createTestUser();
    user.authorizations().add(RoleBasedAuthorization.create("role1"));
    user.authorizations().add(RoleBasedAuthorization.create("role2"));
    testReadWriteUser(user);
  }
  
  @Test
  public void testUniqueAuthorizations() {
    // principal + authorizations
    User user = createTestUser();
    user.authorizations().add(PermissionBasedAuthorization.create("permission1"));
    user.authorizations().add(PermissionBasedAuthorization.create("permission1"));
    user.authorizations().add(RoleBasedAuthorization.create("role1"));
    user.authorizations().add(RoleBasedAuthorization.create("role1"));
    Assert.assertEquals(2, user.authorizations().size());
  }

}
