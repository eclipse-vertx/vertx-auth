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
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthJWTExamples {

  public void example6(Vertx vertx) {

    JsonObject config = new JsonObject().put("keyStore", new JsonObject()
        .put("path", "keystore.jceks")
        .put("type", "jceks")
        .put("password", "secret"));

    AuthProvider provider = JWTAuth.create(vertx, config);
  }

  public void example7(Vertx vertx, String username, String password) {

    JsonObject config = new JsonObject().put("keyStore", new JsonObject()
        .put("path", "keystore.jceks")
        .put("type", "jceks")
        .put("password", "secret"));

    JWTAuth provider = JWTAuth.create(vertx, config);

    // on the verify endpoint once you verify the identity of the user by its username/password
    if ("paulo".equals(username) && "super_secret".equals(password)) {
      String token = provider.generateToken(new JsonObject().put("sub", "paulo"), new JWTOptions());
      // now for any request to protected resources you should pass this string in the HTTP header Authorization as:
      // Authorization: Bearer <token>
    }
  }


}
