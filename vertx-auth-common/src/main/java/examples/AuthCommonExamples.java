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
import io.vertx.ext.auth.*;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;

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

  public void example2(User user, AuthorizationProvider authorizationProvider) {
    // load the authorization for the given user:
    authorizationProvider.getAuthorizations(user, res -> {
      if (res.succeeded()) {
        // cache is populated, perform query
        if (PermissionBasedAuthorization.create("printer1234").match(user)) {
          System.out.println("User has the authority");
        } else {
          System.out.println("User does not have the authority");
        }
      }
    });
  }

  public void example3(User user, AuthorizationProvider authorizationProvider) {
    // load the authorization for the given user:
    authorizationProvider.getAuthorizations(user, res -> {
      if (res.succeeded()) {
        // cache is populated, perform query
        if (RoleBasedAuthorization.create("admin").match(user)) {
          System.out.println("User has the authority");
        } else {
          System.out.println("User does not have the authority");
        }
      }
    });
  }

  public void example4(Vertx vertx) {
    // Generate a secure token of 32 bytes as a base64 string
    String token = VertxContextPRNG.current(vertx).nextString(32);
    // Generate a secure random integer
    int randomInt = VertxContextPRNG.current(vertx).nextInt();
  }

  public void example5() {
    KeyStoreOptions options = new KeyStoreOptions()
      .setPath("/path/to/keystore/file")
      .setType("pkcs8")
      .setPassword("keystore-password")
      .putPasswordProtection("key-alias", "alias-password");
  }

  public void example6(Vertx vertx) {
    PubSecKeyOptions options = new PubSecKeyOptions()
      .setAlgorithm("RS256")
      .setBuffer(vertx.fileSystem().readFileBlocking("/path/to/pem/file").toString());
  }

  public void example7(Vertx vertx, AuthenticationProvider ldapAuthProvider, AuthenticationProvider propertiesAuthProvider) {
    // users will be checked on the 2 providers
    // and on the first success the operation completes
    ChainAuth.any()
      .add(ldapAuthProvider)
      .add(propertiesAuthProvider);
  }

  public void example8(Vertx vertx, AuthenticationProvider ldapAuthProvider, AuthenticationProvider propertiesAuthProvider) {
    // users will be checked on the 2 providers
    // and on all providers success the operation completes
    ChainAuth.all()
      .add(ldapAuthProvider)
      .add(propertiesAuthProvider);
  }
}
