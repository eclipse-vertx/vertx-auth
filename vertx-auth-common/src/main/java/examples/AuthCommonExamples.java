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
import io.vertx.ext.auth.VertxContextPRNG;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthCommonExamples {

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

    user.isAuthorized("printers:printer1234", res -> {
      if (res.succeeded()) {

        boolean hasAuthority = res.result();

        if (hasAuthority) {
          System.out.println("User has the authority");
        } else {
          System.out.println("User does not have the authority");
        }

      } else {
        res.cause().printStackTrace();
      }
    });
  }

  public void example3(User user) {

    user.isAuthorized("role:admin", res -> {
      if (res.succeeded()) {

        boolean hasAuthority = res.result();

        if (hasAuthority) {
          System.out.println("User has the authority to the role of admin");
        } else {
          System.out.println("User does not have the authority");
        }

      } else {
        res.cause().printStackTrace();
      }
    });
  }

  public void example4(Vertx vertx) {
    // Generate a secure token of 32 bytes as a base64 string
    String token = VertxContextPRNG.current(vertx).nextString(32);
    // Generate a secure random integer
    int randomInt = VertxContextPRNG.current(vertx).nextInt();
  }
}
