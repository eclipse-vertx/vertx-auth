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
import io.vertx.ext.jwt.JWTOptions;

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
    user.isAuthorized("create-report", res -> {
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

    AuthProvider provider = JWTAuth.create(vertx, new JWTAuthOptions(config));
  }

  public void example15(Vertx vertx) {
    JWTAuth provider = JWTAuth.create(vertx, new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS256")
        .setPublicKey(
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxPSbCQY5mBKFDIn1kggv\n" +
            "Wb4ChjrctqD4nFnJOJk4mpuZ/u3h2ZgeKJJkJv8+5oFO6vsEwF7/TqKXp0XDp6IH\n" +
            "byaOSWdkl535rCYR5AxDSjwnuSXsSp54pvB+fEEFDPFF81GHixepIbqXCB+BnCTg\n" +
            "N65BqwNn/1Vgqv6+H3nweNlbTv8e/scEgbg6ZYcsnBBB9kYLp69FSwNWpvPmd60e\n" +
            "3DWyIo3WCUmKlQgjHL4PHLKYwwKgOHG/aNl4hN4/wqTixCAHe6KdLnehLn71x+Z0\n" +
            "SyXbWooftefpJP1wMbwlCpH3ikBzVIfHKLWT9QIOVoRgchPU3WAsZv/ePgl5i8Co\n" +
            "qwIDAQAB")
        .setSecretKey(
          "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE9JsJBjmYEoUM\n" +
            "ifWSCC9ZvgKGOty2oPicWck4mTiam5n+7eHZmB4okmQm/z7mgU7q+wTAXv9Oopen\n" +
            "RcOnogdvJo5JZ2SXnfmsJhHkDENKPCe5JexKnnim8H58QQUM8UXzUYeLF6khupcI\n" +
            "H4GcJOA3rkGrA2f/VWCq/r4fefB42VtO/x7+xwSBuDplhyycEEH2Rgunr0VLA1am\n" +
            "8+Z3rR7cNbIijdYJSYqVCCMcvg8cspjDAqA4cb9o2XiE3j/CpOLEIAd7op0ud6Eu\n" +
            "fvXH5nRLJdtaih+15+kk/XAxvCUKkfeKQHNUh8cotZP1Ag5WhGByE9TdYCxm/94+\n" +
            "CXmLwKirAgMBAAECggEAeQ+M+BgOcK35gAKQoklLqZLEhHNL1SnOhnQd3h84DrhU\n" +
            "CMF5UEFTUEbjLqE3rYGP25mdiw0ZSuFf7B5SrAhJH4YIcZAO4a7ll23zE0SCW+/r\n" +
            "zr9DpX4Q1TP/2yowC4uGHpBfixxpBmVljkWnai20cCU5Ef/O/cAh4hkhDcHrEKwb\n" +
            "m9nymKQt06YnvpCMKoHDdqzfB3eByoAKuGxo/sbi5LDpWalCabcg7w+WKIEU1PHb\n" +
            "Qi+RiDf3TzbQ6TYhAEH2rKM9JHbp02TO/r3QOoqHMITW6FKYvfiVFN+voS5zzAO3\n" +
            "c5X4I+ICNzm+mnt8wElV1B6nO2hFg2PE9uVnlgB2GQKBgQD8xkjNhERaT7f78gBl\n" +
            "ch15DRDH0m1rz84PKRznoPrSEY/HlWddlGkn0sTnbVYKXVTvNytKSmznRZ7fSTJB\n" +
            "2IhQV7+I0jeb7pyLllF5PdSQqKTk6oCeL8h8eDPN7awZ731zff1AGgJ3DJXlRTh/\n" +
            "O6zj9nI8llvGzP30274I2/+cdwKBgQDHd/twbiHZZTDexYewP0ufQDtZP1Nk54fj\n" +
            "EpkEuoTdEPymRoq7xo+Lqj5ewhAtVKQuz6aH4BeEtSCHhxy8OFLDBdoGCEd/WBpD\n" +
            "f+82sfmGk+FxLyYkLxHCxsZdOb93zkUXPCoCrvNRaUFO1qq5Dk8eftGCdC3iETHE\n" +
            "6h5avxHGbQKBgQCLHQVMNhL4MQ9slU8qhZc627n0fxbBUuhw54uE3s+rdQbQLKVq\n" +
            "lxcYV6MOStojciIgVRh6FmPBFEvPTxVdr7G1pdU/k5IPO07kc6H7O9AUnPvDEFwg\n" +
            "suN/vRelqbwhufAs85XBBY99vWtxdpsVSt5nx2YvegCgdIj/jUAU2B7hGQKBgEgV\n" +
            "sCRdaJYr35FiSTsEZMvUZp5GKFka4xzIp8vxq/pIHUXp0FEz3MRYbdnIwBfhssPH\n" +
            "/yKzdUxcOLlBtry+jgo0nyn26/+1Uyh5n3VgtBBSePJyW5JQAFcnhqBCMlOVk5pl\n" +
            "/7igiQYux486PNBLv4QByK0gV0SPejDzeqzIyB+xAoGAe5if7DAAKhH0r2M8vTkm\n" +
            "JvbCFjwuvhjuI+A8AuS8zw634BHne2a1Fkvc8c3d9VDbqsHCtv2tVkxkKXPjVvtB\n" +
            "DtzuwUbp6ebF+jOfPK0LDuJoTdTdiNjIcXJ7iTTI3cXUnUNWWphYnFogzPFq9CyL\n" +
            "0fPinYmDJpkwMYHqQaLGQyg=")
      ));

    String token = provider.generateToken(new JsonObject(), new io.vertx.ext.jwt.JWTOptions().setAlgorithm("RS256"));
  }

  public void example16(Vertx vertx) {
    JWTAuth provider = JWTAuth.create(vertx, new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("HS256")
        .setPublicKey("keyboard cat")
        .setSymmetric(true)));

    String token = provider.generateToken(new JsonObject());
  }

  public void example17(Vertx vertx) {
    JWTAuth provider = JWTAuth.create(vertx, new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("ES256")
        .setSecretKey(
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeRyEfU1NSHPTCuC9\n" +
            "rwLZMukaWCH2Fk6q5w+XBYrKtLihRANCAAStpUnwKmSvBM9EI+W5QN3ALpvz6bh0\n" +
            "SPCXyz5KfQZQuSj4f3l+xNERDUDaygIUdLjBXf/bc15ur2iZjcq4r0Mr")
      ));

    String token = provider.generateToken(new JsonObject(), new io.vertx.ext.jwt.JWTOptions().setAlgorithm("ES256"));
  }

  public void example18(Vertx vertx) {
    JWTAuth provider = JWTAuth.create(vertx, new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("ES256")
        .setPublicKey(
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEraVJ8CpkrwTPRCPluUDdwC6b8+m4\n" +
            "dEjwl8s+Sn0GULko+H95fsTREQ1A2soCFHS4wV3/23Nebq9omY3KuK9DKw==\n")
        .setSecretKey(
          "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeRyEfU1NSHPTCuC9\n" +
            "rwLZMukaWCH2Fk6q5w+XBYrKtLihRANCAAStpUnwKmSvBM9EI+W5QN3ALpvz6bh0\n" +
            "SPCXyz5KfQZQuSj4f3l+xNERDUDaygIUdLjBXf/bc15ur2iZjcq4r0Mr")
      ));

    String token = provider.generateToken(new JsonObject(), new io.vertx.ext.jwt.JWTOptions().setAlgorithm("ES256"));
  }
}
