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
import io.vertx.ext.auth.shiro.ShiroAuth;
import io.vertx.ext.auth.shiro.ShiroAuthOptions;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;
import org.apache.shiro.realm.Realm;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthShiroExamples {


  public void example3(Vertx vertx) {

    JsonObject config = new JsonObject().put("properties_path", "classpath:test-auth.properties");

    AuthProvider provider = ShiroAuth.create(vertx, new ShiroAuthOptions().setType(ShiroAuthRealmType.PROPERTIES).setConfig(config));

  }



  public void example4(AuthProvider authProvider) {

    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");

    authProvider.authenticate(authInfo, res -> {
      if (res.succeeded()) {
        User user = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example5(User user) {

    user.isAuthorized("newsletter:edit:13", res -> {
      if (res.succeeded()) {
        boolean hasPermission = res.result();
      } else {
        // Failed to
      }
    });

  }

  public void example6(User user) {

    user.isAuthorized("role:manager", res -> {
      if (res.succeeded()) {
        boolean hasRole = res.result();
      } else {
        // Failed to
      }
    });

  }



  public void example8(Vertx vertx, Realm realm) {

    AuthProvider provider = ShiroAuth.create(vertx, realm);

  }
}
