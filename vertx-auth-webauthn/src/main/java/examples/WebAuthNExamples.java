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

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.Authenticator;
import io.vertx.ext.auth.webauthn.RelyingParty;
import io.vertx.ext.auth.webauthn.WebAuthn;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;

import java.util.List;

/**
 * @author Paulo Lopes
 */
public class WebAuthNExamples {

  public void example1(Vertx vertx, List<Authenticator> authenticators) {
    WebAuthn webAuthN = WebAuthn.create(
      vertx,
      new WebAuthnOptions()
        .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .authenticatorFetcher(query -> {
        // function that fetches some authenticators from a
        // persistence storage
        return Future.succeededFuture(authenticators);
      })
      .authenticatorUpdater(authenticator -> {
        // function that updates an authenticator to a
        // persistence storage
        return Future.succeededFuture();
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
    WebAuthn webAuthN = WebAuthn.create(
      vertx,
      new WebAuthnOptions()
        .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .authenticatorFetcher(query -> {
        // function that fetches some authenticators from a
        // persistence storage
        return Future.succeededFuture(authenticators);
      })
      .authenticatorUpdater(authenticator -> {
        // function that updates an authenticator to a
        // persistence storage
        return Future.succeededFuture();
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
        new JsonObject()
          // the username you want to link to
          .put("username", "paulo")
          // the server origin
          .put("origin", "https://192.168.178.206.xip.io:8443")
          // the server domain
          .put("domain", "192.168.178.206.xip.io")
          // the challenge given on the previous step
          .put("challenge", "BH7EKIDXU6Ct_96xTzG0l62qMhW_Ef_K4MQdDLoVNc1UX...")
          .put("webauthn", request))
      .onSuccess(user -> {
        // success!
      });
  }

  public void example3(Vertx vertx, List<Authenticator> authenticators) {
    WebAuthn webAuthN = WebAuthn.create(
      vertx,
      new WebAuthnOptions()
        .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .authenticatorFetcher(query -> {
        // function that fetches some authenticators from a
        // persistence storage
        return Future.succeededFuture(authenticators);
      })
      .authenticatorUpdater(authenticator -> {
        // function that updates an authenticator to a
        // persistence storage
        return Future.succeededFuture();
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
    WebAuthn webAuthN = WebAuthn.create(
      vertx,
      new WebAuthnOptions()
        .setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .authenticatorFetcher(query -> {
        // function that fetches some authenticators from a
        // persistence storage
        return Future.succeededFuture(authenticators);
      })
      .authenticatorUpdater(authenticator -> {
        // function that updates an authenticator to a
        // persistence storage
        return Future.succeededFuture();
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

    webAuthN.authenticate(new JsonObject()
      // the username you want to link to
      .put("username", "paulo")
      // the server origin
      .put("origin", "https://192.168.178.206.xip.io:8443")
      // the server domain
      .put("domain", "192.168.178.206.xip.io")
      // the challenge given on the previous step
      .put("challenge", "BH7EKIDXU6Ct_96xTzG0l62qMhW_Ef_K4MQdDLoVNc1UX...")
      .put("webauthn", body))
      .onSuccess(user -> {
        // success!
      });
  }

  public void example5(Vertx vertx) {
    // fido2 MDS config
    final WebAuthnOptions webAuthnOptions = new WebAuthnOptions()
      // in order to fully trust the MDS tokens we should load the CRLs as
      // described on https://fidoalliance.org/metadata/

      // here the content of: http://crl.globalsign.net/Root.crl
      .addRootCrl(
        "MIIB1jCCAV0CAQEwCg...");

    // create the webauthn security object like before
    final WebAuthn webAuthN = WebAuthn.create(vertx, webAuthnOptions);

    webAuthN.metaDataService()
      .fetchTOC()
      .onSuccess(allOk -> {
        // if all metadata was downloaded and parsed correctly allOk is true
        // the processing will not stop if a entry is corrupt, in that case that
        // specific entry is skipped and the flag is false. That also means that
        // that entry will be tagged and "not trustable" as we can't make any
        // valid decision.
      });
  }

  public void example6(Vertx vertx) {
    final WebAuthnOptions webAuthnOptions = new WebAuthnOptions()
      // fido2 MDS custom ROOT certificate
      .putRootCertificate("mds", "MIIB1jCCAV0CAQEwCg...")
      // updated google root certificate from (https://pki.goog/repository/)
      .putRootCertificate("android-safetynet", "MIIDvDCCAqSgAwIBAgINAgPk9GHs...");
  }
}
