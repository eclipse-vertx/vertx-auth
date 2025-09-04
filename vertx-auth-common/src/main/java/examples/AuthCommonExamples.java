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
import io.vertx.ext.auth.*;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.prng.VertxContextPRNG;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthCommonExamples {

  public void example1(AuthenticationProvider authProvider) {

    Credentials authInfo =
      new UsernamePasswordCredentials("tim", "mypassword");

    authProvider.authenticate(authInfo)
      .onSuccess(user -> {
        System.out.println("User " + user.principal() + " is now authenticated");
      })
      .onFailure(Throwable::printStackTrace);
  }

  public void example2(User user, AuthorizationProvider authorizationProvider) {
    // load the authorization for the given user:
    authorizationProvider.getAuthorizations(user)
      .onSuccess(done -> {
        // cache is populated, perform query
        if (PermissionBasedAuthorization.create("printer1234").match(user)) {
          System.out.println("User has the authority");
        } else {
          System.out.println("User does not have the authority");
        }
      });
  }

  public void example3(User user, AuthorizationProvider authorizationProvider) {
    // load the authorization for the given user:
    authorizationProvider.getAuthorizations(user)
      .onSuccess(done -> {
        // cache is populated, perform query
        if (RoleBasedAuthorization.create("admin").match(user)) {
          System.out.println("User has the authority");
        } else {
          System.out.println("User does not have the authority");
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
      .setBuffer(
        vertx.fileSystem()
          .readFileBlocking("/path/to/pem/file")
          .toString());
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

  public void example9(User user) {

    // check if user has a well known property
    if (user.containsKey("sub")) {
      // the check will first assert that the attributes contain
      // the given key and if not assert that the principal contains
      // the given key

      // just like the check before the get will follow the same
      // rules to retrieve the data, first "attributes" then "principal"
      String sub = user.get("sub");
    }
  }
}