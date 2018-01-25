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
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.jwt.JWTOptions;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthJWTExamples {

  public void example6(Vertx vertx) {

    JWTAuthOptions config = new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("keystore.jceks")
        .setPassword("secret"));

    AuthProvider provider = JWTAuth.create(vertx, config);
  }

  public void example7(Vertx vertx, String username, String password) {

    JWTAuthOptions config = new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("keystore.jceks")
        .setPassword("secret"));

    JWTAuth provider = JWTAuth.create(vertx, config);

    // on the verify endpoint once you verify the identity of the user by its username/password
    if ("paulo".equals(username) && "super_secret".equals(password)) {
      String token = provider.generateToken(new JsonObject().put("sub", "paulo"), new JWTOptions());
      // now for any request to protected resources you should pass this string in the HTTP header Authorization as:
      // Authorization: Bearer <token>
    }
  }

  public void example8(Vertx vertx) {

    JWTAuthOptions config = new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS256")
        .setPublicKey("BASE64-ENCODED-PUBLIC_KEY"));

    AuthProvider provider = JWTAuth.create(vertx, config);
  }

  public void example9(JWTAuth jwtAuth) {
    // This string is what you see after the string "Bearer" in the
    // HTTP Authorization header
    jwtAuth.authenticate(new JsonObject().put("jwt", "BASE64-ENCODED-STRING"), res -> {
      if (res.succeeded()) {
        User theUser = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example10(JWTAuth jwtAuth) {

    // This string is what you see after the string "Bearer" in the
    // HTTP Authorization header

    // In this case we are forcing the provider to ignore the `exp` field
    jwtAuth.authenticate(new JsonObject()
      .put("jwt", "BASE64-ENCODED-STRING")
      .put("options", new JsonObject()
        .put("ignoreExpiration", true)), res -> {
      if (res.succeeded()) {
        User theUser = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example11(JWTAuth jwtAuth) {

    // This string is what you see after the string "Bearer" in the
    // HTTP Authorization header

    // In this case we are forcing the provider to ignore the `exp` field
    jwtAuth.authenticate(new JsonObject()
      .put("jwt", "BASE64-ENCODED-STRING")
      .put("options", new JsonObject()
        .put("audience", new JsonArray().add("paulo@server.com"))), res -> {
      if (res.succeeded()) {
        User theUser = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example12(JWTAuth jwtAuth) {

    // This string is what you see after the string "Bearer" in the
    // HTTP Authorization header

    // In this case we are forcing the provider to ignore the `exp` field
    jwtAuth.authenticate(new JsonObject()
      .put("jwt", "BASE64-ENCODED-STRING")
      .put("options", new JsonObject()
        .put("issuer", "mycorp.com")), res -> {
      if (res.succeeded()) {
        User theUser = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example13(User user) {
    user.isAuthorised("create-report", res -> {
      if (res.succeeded() && res.result()) {
        // Yes the user can create reports
      }
    });
  }


  public void example14(Vertx vertx) {

    JsonObject config = new JsonObject()
      .put("public-key", "BASE64-ENCODED-PUBLIC_KEY")
      // since we're consuming keycloak JWTs we need to locate the permission claims in the token
      .put("permissionsClaimKey", "realm_access/roles");

    AuthProvider provider = JWTAuth.create(vertx, config);
  }
}
