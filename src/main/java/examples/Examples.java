/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package examples;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;
import io.vertx.ext.jdbc.JDBCClient;
import org.apache.shiro.realm.Realm;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class Examples {

  public void example1(AuthProvider authProvider) {

    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "mypassword");

    authProvider.authenticate(authInfo, res -> {
      if (res.succeeded()) {

        User user = res.result();

        System.out.println("User " + user.principal() + " is now authenticated");

      } else {
        res.cause().printStackTrace();
      }
    });
  }

  public void example2(User user) {

    user.hasPermission("admin", res -> {
      if (res.succeeded()) {

        boolean hasPermission = res.result();

        if (hasPermission) {
          System.out.println("User has the permision");
        } else {
          System.out.println("User does not have the permision");
        }

      } else {
        res.cause().printStackTrace();
      }
    });
  }

  public void example3(Vertx vertx) {

    JsonObject config = new JsonObject().put("properties_path", "classpath:test-auth.properties");

    AuthProvider provider = ShiroAuth.create(vertx, ShiroAuthRealmType.PROPERTIES, config);

  }

  public void example4(Vertx vertx, Realm realm) {

    AuthProvider provider = ShiroAuth.create(vertx, realm);

  }

  public void example5(Vertx vertx, JsonObject jdbcClientConfig) {

    JDBCClient jdbcClient = JDBCClient.createShared(vertx, jdbcClientConfig);

    JDBCAuth authProvider = JDBCAuth.create(jdbcClient);
  }

  public void example6() {

    JsonObject config = new JsonObject()
        .put("keyStoreURI", "classpath:///keystore.jceks")
        .put("keyStoreType", "jceks")
        .put("keyStorePassword", "secret");

    AuthProvider provider = JWTAuth.create(config);
  }

  public void example7(String username, String password) {

    JsonObject config = new JsonObject()
            .put("keyStoreURI", "classpath:///keystore.jceks")
            .put("keyStoreType", "jceks")
            .put("keyStorePassword", "secret");

    JWTAuth provider = JWTAuth.create(config);

    // on the verify endpoint once you verify the identity of the user by its username/password
    if ("paulo".equals(username) && "super_secret".equals(password)) {
      String token = provider.generateToken(new JsonObject().put("sub", "paulo"), new JWTOptions());
      // now for any request to protected resources you should pass this string in the HTTP header Authorization as:
      // Authorization: Bearer <token>
    }
  }


}
