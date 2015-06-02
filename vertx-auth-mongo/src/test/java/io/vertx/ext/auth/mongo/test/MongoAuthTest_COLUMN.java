package io.vertx.ext.auth.mongo.test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.HashStrategy.SaltStyle;
import io.vertx.ext.auth.mongo.MongoAuth;

import java.util.List;

/**
 * Testing MongoAuth setting the salt to a column in the user<br>
 * <br>
 * Copyright: Copyright (c) 02.06.2015 <br>
 * Company: Braintags GmbH <br>
 * 
 * @author mremme
 */

public class MongoAuthTest_COLUMN extends MongoAuthTestNO_SALT {

  /**
   * 
   */
  public MongoAuthTest_COLUMN() {
  }

  @Override
  protected JsonObject createAuthServiceConfig() {
    JsonObject js = new JsonObject();
    js.put(MongoAuth.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuth.DEFAULT_COLLECTION_NAME));
    js.put(MongoAuth.PROPERTY_SALT_STYLE, SaltStyle.COLUMN);
    return js;
  }

  @Override
  protected void initAuthService() throws Exception {
    super.initAuthService();
    assertEquals(SaltStyle.COLUMN, authProvider.getHashStrategy().getSaltStyle());
  }

  /**
   * Creates a user as {@link JsonObject}
   * 
   * @param username
   * @param password
   * @return
   */
  @Override
  protected User createUser(String username, String password, List<String> roles, List<String> permissions) {
    User user = super.createUser(username, password, roles, permissions);
    String salt = user.principal().getString(authProvider.getSaltField());
    assertTrue("No salt in user created", salt != null && !salt.isEmpty());
    return user;
  }

}
