/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package examples;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.htpasswd.HtpasswdAuth;
import io.vertx.ext.auth.htpasswd.HtpasswdAuthOptions;

/**
 *
 * @author Neven Radovanović
 */
public class AuthHtpasswdExamples {

  public void example1(Vertx vertx) {
    HtpasswdAuth authProvider = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions());
  }

  public void example2(HtpasswdAuth authProvider) {
    JsonObject authInfo = new JsonObject()
      .put("username", "someUser")
      .put("password", "somePassword");

    authProvider.authenticate(authInfo, res -> {
      if (res.succeeded()) {
        User user = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example3(Vertx vertx) {
    HtpasswdAuth authProviderUsersAuthorizedForNothing = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().setUsersAuthorizedForEverything(false));
    HtpasswdAuth authProviderUsersAuthorizedForEverything = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().setUsersAuthorizedForEverything(true));
  }

  public void example4(User user) {
    user.isAuthorised("anyAuthority", res -> {
      if (res.succeeded()) {
        boolean hasRole = res.result();
      } else {
        // Failed
      }
    });
  }

}
