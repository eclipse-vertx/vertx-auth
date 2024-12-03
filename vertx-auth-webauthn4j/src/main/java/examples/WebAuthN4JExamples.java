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

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn4j.*;

import java.util.List;

/**
 * @author Paulo Lopes
 */
public class WebAuthN4JExamples {

  public void example1(Vertx vertx, List<Authenticator> authenticators) {
    WebAuthn4J webAuthN = WebAuthn4J.create(
        vertx,
        new WebAuthn4JOptions()
          .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .credentialStorage(new CredentialStorage() {
        @Override
        public Future<List<Authenticator>> find(@Nullable String userName, @Nullable String credentialId) {
          // function that fetches some authenticators from a
          // persistence storage
          return Future.succeededFuture(authenticators);
        }
        @Override
        public Future<Void> storeCredential(Authenticator authenticator) {
          // function that stores an authenticator to a
          // persistence storage
          return Future.succeededFuture();
        }
        @Override
        public Future<Void> updateCounter(Authenticator authenticator) {
          // function that updates an authenticator to a
          // persistence storage
          return Future.succeededFuture();
        }
      });

    // some user
    JsonObject user = new JsonObject()
      // id is expected to be a base64url string
      .put("id", "000000000000000000000000")
      .put("rawId", "000000000000000000000000")
      .put("name", "john.doe@email.com")
      // optionally
      .put("displayName", "John Doe")
      .put("icon", "https://pics.example.com/00/p/aBjjjpqPb.png");

    webAuthN
      .createCredentialsOptions(user)
      .onSuccess(challengeResponse -> {
        // return the challenge to the browser
        // for further processing
      });
  }

  public void example2(Vertx vertx, List<Authenticator> authenticators) {
    WebAuthn4J webAuthN = WebAuthn4J.create(
        vertx,
        new WebAuthn4JOptions()
          .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
        .credentialStorage(new CredentialStorage() {
          @Override
          public Future<List<Authenticator>> find(@Nullable String userName, @Nullable String credentialId) {
            // function that fetches some authenticators from a
            // persistence storage
            return Future.succeededFuture(authenticators);
          }
          @Override
          public Future<Void> storeCredential(Authenticator authenticator) {
            // function that stores an authenticator to a
            // persistence storage
            return Future.succeededFuture();
          }
          @Override
          public Future<Void> updateCounter(Authenticator authenticator) {
            // function that updates an authenticator to a
            // persistence storage
            return Future.succeededFuture();
          }
        });

    // the response received from the browser
    JsonObject request = new JsonObject()
      .put("id", "Q-MHP0Xq20CKM5LW3qBt9gu5vdOYLNZc3jCcgyyL...")
      .put("rawId", "Q-MHP0Xq20CKM5LW3qBt9gu5vdOYLNZc3jCcgyyL...")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("attestationObject", "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVj...")
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlb..."));

    webAuthN
      .authenticate(
        new WebAuthn4JCredentials()
          // the username you want to link to
          .setUsername("paulo")
          // the server origin
          .setOrigin("https://192.168.178.206.xip.io:8443")
          // the server domain
          .setDomain("192.168.178.206.xip.io")
          // the challenge given on the previous step
          .setChallenge("BH7EKIDXU6Ct_96xTzG0l62qMhW_Ef_K4MQdDLoVNc1UX...")
          .setWebauthn(request))
      .onSuccess(user -> {
        // success!
      });
  }

  public void example3(Vertx vertx, List<Authenticator> authenticators) {
    WebAuthn4J webAuthN = WebAuthn4J.create(
        vertx,
        new WebAuthn4JOptions()
          .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
        .credentialStorage(new CredentialStorage() {
          @Override
          public Future<List<Authenticator>> find(@Nullable String userName, @Nullable String credentialId) {
            // function that fetches some authenticators from a
            // persistence storage
            return Future.succeededFuture(authenticators);
          }
          @Override
          public Future<Void> storeCredential(Authenticator authenticator) {
            // function that stores an authenticator to a
            // persistence storage
            return Future.succeededFuture();
          }
          @Override
          public Future<Void> updateCounter(Authenticator authenticator) {
            // function that updates an authenticator to a
            // persistence storage
            return Future.succeededFuture();
          }
        });

    // Login only requires the username and can even be set to null if
    // resident keys are supported, in this case the authenticator remembers
    // the public key used for the relying party
    webAuthN.getCredentialsOptions("paulo")
      .onSuccess(challengeResponse -> {
        // return the challenge to the browser
        // for further processing
      });
  }

  public void example4(Vertx vertx, List<Authenticator> authenticators) {
    WebAuthn4J webAuthN = WebAuthn4J.create(
        vertx,
        new WebAuthn4JOptions()
          .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
        .credentialStorage(new CredentialStorage() {
          @Override
          public Future<List<Authenticator>> find(@Nullable String userName, @Nullable String credentialId) {
            // function that fetches some authenticators from a
            // persistence storage
            return Future.succeededFuture(authenticators);
          }
          @Override
          public Future<Void> storeCredential(Authenticator authenticator) {
            // function that stores an authenticator to a
            // persistence storage
            return Future.succeededFuture();
          }
          @Override
          public Future<Void> updateCounter(Authenticator authenticator) {
            // function that updates an authenticator to a
            // persistence storage
            return Future.succeededFuture();
          }
        });

    // The response from the login challenge request
    JsonObject body = new JsonObject()
      .put("id", "rYLaf9xagyA2YnO-W3CZDW8udSg8VeMMm25nenU7nCSxUqy1pEzOdb9o...")
      .put("rawId", "rYLaf9xagyA2YnO-W3CZDW8udSg8VeMMm25nenU7nCSxUqy1pEzOdb9o...")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("authenticatorData", "fxV8VVBPmz66RLzscHpg5yjRhO...")
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlb...")
        .put("signature", "MEUCIFXjL0ONRuLP1hkdlRJ8d0ofuRAS12c6w8WgByr-0yQZA...")
        .put("userHandle", ""));

    webAuthN.authenticate(new WebAuthn4JCredentials()
        // the username you want to link to
        .setUsername("paulo")
        // the server origin
        .setOrigin("https://192.168.178.206.xip.io:8443")
        // the server domain
        .setDomain("192.168.178.206.xip.io")
        // the challenge given on the previous step
        .setChallenge("BH7EKIDXU6Ct_96xTzG0l62qMhW_Ef_K4MQdDLoVNc1UX...")
        .setWebauthn(body))
      .onSuccess(user -> {
        // success!
      });
  }

  public void example5(Vertx vertx) {
    final WebAuthn4JOptions webAuthnOptions = new WebAuthn4JOptions()
        // Use FIDO metadata
        .setUseMetadata(true);
  }

  public void example6(Vertx vertx) {
    final WebAuthn4JOptions webAuthnOptions = new WebAuthn4JOptions()
      // fido2 MDS custom ROOT certificate
      .putRootCertificate("mds", "MIIB1jCCAV0CAQEwCg...")
      // updated google root certificate from (https://pki.goog/repository/)
      .putRootCertificate("android-safetynet", "MIIDvDCCAqSgAwIBAgINAgPk9GHs...");
  }
}
