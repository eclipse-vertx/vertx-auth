/*
 * Copyright 2019 Red Hat, Inc.
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

package io.vertx.ext.auth.webauthn.impl;

import com.fasterxml.jackson.core.JsonParser;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthStore;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.webauthn.*;
import io.vertx.ext.auth.webauthn.impl.attestation.Attestation;
import io.vertx.ext.auth.webauthn.impl.attestation.AttestationException;
import io.vertx.ext.jwt.JWK;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class WebAuthNImpl implements WebAuthN {

  private static final Logger LOG = LoggerFactory.getLogger(WebAuthNImpl.class);

  // codecs
  private final Base64.Encoder b64enc = Base64.getUrlEncoder().withoutPadding();
  private final Base64.Decoder b64dec = Base64.getUrlDecoder();

  private final MessageDigest sha256;
  private final PRNG random;
  private final WebAuthNOptions options;
  private final AuthStore store;

  private final Map<String, Attestation> attestations = new HashMap<>();

  public WebAuthNImpl(Vertx vertx, WebAuthNOptions options, AuthStore store) {
    random = new PRNG(vertx);
    this.options = Objects.requireNonNull(options);
    this.store = Objects.requireNonNull(store);

    ServiceLoader<Attestation> attestationServiceLoader = ServiceLoader.load(Attestation.class);

    for (Attestation att : attestationServiceLoader) {
      attestations.put(att.fmt(), att);
    }
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException nsae) {
      throw new IllegalStateException("SHA-256 is not available", nsae);
    }
  }

  private String randomBase64URLBuffer(int length) {
    final byte[] buff = new byte[length];
    random.nextBytes(buff);
    return b64enc.encodeToString(buff);
  }

  @Override
  public WebAuthN createCredentialsOptions(JsonObject user, CredentialsChallengeType type, Handler<AsyncResult<JsonObject>> handler) {

    store.getUserCredentials(user.getString("name"), getUserCredentials -> {
      if (getUserCredentials.failed()) {
        handler.handle(Future.failedFuture(getUserCredentials.cause()));
        return;
      }

      List<JsonObject> credentials = getUserCredentials.result();

      if (credentials == null || credentials.size() == 0 || (credentials.size() == 1 && credentials.get(0).getBoolean("registered", false))) {

        final String id = randomBase64URLBuffer(32);

        // STEP 2 Generate Credential Challenge
        JsonObject authenticatorSelection;

        switch (type) {
          case CROSS_PLATFORM:
            // STEP 3.1 add this for security key
            authenticatorSelection = new JsonObject()
              .put("authenticatorAttachment", "cross-platform")
              .put("requireResidentKey", false);
            break;
          case PLATFORM:
            // STEP 3.2 Add this for finger print
            authenticatorSelection = new JsonObject()
              .put("authenticatorAttachment", "platform")
              .put("requireResidentKey", false)
              .put("userVerification", "required");
            break;
          default:
            handler.handle(Future.failedFuture("Unsupported Authenticator Attachment type: " + type));
            return;
        }

        final JsonArray pubKeyCredParams = new JsonArray();

        for (String pubKeyCredParam : options.getPubKeyCredParams()) {
          switch (pubKeyCredParam) {
            case "ES256":
              pubKeyCredParams.add(
                new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -7));
              break;
//            case "EdDSA":
//              pubKeyCredParams.add(
//                new JsonObject()
//                  .put("type", "public-key")
//                  .put("alg", -8));
//              break;
            case "ES384":
              pubKeyCredParams.add(
                new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -35));
              break;
            case "ES512":
              pubKeyCredParams.add(
                new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -36));
              break;
            case "RS256":
              pubKeyCredParams.add(
                new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -257));
              break;
            case "RS384":
              pubKeyCredParams.add(
                new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -258));
              break;
            case "RS512":
              pubKeyCredParams.add(
                new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -259));
              break;
            case "RS1":
              pubKeyCredParams.add(
                new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -65535));
              break;
            default:
              LOG.warn("Unsupported algorithm: " + pubKeyCredParam);
          }
        }

        // relay party configuration
        final JsonObject rp = new JsonObject()
          .put("name", options.getRealm())
          .put("displayName", options.getRealmDisplayName());

        if (options.getRealmIcon() != null) {
          rp.put("icon", options.getRealmIcon());
        }
        if (options.getRealmId() != null) {
          rp.put("id", options.getRealmId());
        }

        // user configuration
        final JsonObject _user = new JsonObject()
          .put("id", id)
          .put("name", user.getString("name"))
          .put("displayName", user.getString("displayName"));

        if (user.getString("icon") != null) {
          _user.put("icon", user.getString("icon"));
        }

        handler.handle(Future.succeededFuture(
          new JsonObject()
            .put("challenge", randomBase64URLBuffer(32))
            .put("rp", rp)
            .put("user", _user)
            .put("authenticatorSelection", authenticatorSelection)
            .put("attestation", options.getAttestation())
            .put("pubKeyCredParams", pubKeyCredParams)));
      }
    });

    return this;
  }

  @Override
  public WebAuthN getCredentialsOptions(String username, Handler<AsyncResult<JsonObject>> handler) {

    store.getUserCredentials(username, getUserCredentials -> {
      if (getUserCredentials.failed()) {
        handler.handle(Future.failedFuture(getUserCredentials.cause()));
        return;
      }

      List<JsonObject> credentials = getUserCredentials.result();

      if (credentials == null) {
        handler.handle(Future.failedFuture("Invalid username/account disabled."));
        return;
      }

      JsonArray allowCredentials = new JsonArray();

      JsonArray transports = new JsonArray();

      for (String transport : options.getTransports()) {
        transports.add(transport);
      }

      // STEP 19 Return allow credential ID
      for (JsonObject cred : credentials) {
        String credId = cred.getString("credID");
        if (credId != null) {
          allowCredentials
            .add(new JsonObject()
              .put("type", "public-key")
              .put("id", credId)
              .put("transports", transports));
        }
      }

      handler.handle(Future.succeededFuture(
        new JsonObject()
          .put("challenge", randomBase64URLBuffer(options.getChallengeLength()))
          .put("allowCredentials", allowCredentials)
      ));
    });

    return this;
  }

  @Override
  public void authenticate(WebAuthNInfo authInfo, Handler<AsyncResult<User>> handler) {
    //    {
    //      "rawId": "base64url",
    //      "id": "base64url",
    //      "response": {
    //        "attestationObject": "base64url",
    //        "clientDataJSON": "base64url"
    //      },
    //      "getClientExtensionResults": {},
    //      "type": "public-key"
    //    }
    final JsonObject webauthnResp = Objects.requireNonNull(authInfo.getWebauthn());
    // TODO: if username is null maybe use authInfo.id ?
    final String username = Objects.requireNonNull(authInfo.getUsername());

    // response can't be null
    final JsonObject response = Objects.requireNonNull(webauthnResp.getJsonObject("response"));

    byte[] clientDataJSON = b64dec.decode(response.getString("clientDataJSON"));
    JsonObject clientData = new JsonObject(Buffer.buffer(clientDataJSON));

    // Verify challenge is match with session
    if (!clientData.getString("challenge").equals(authInfo.getChallenge())) {
      handler.handle(Future.failedFuture("Challenges don't match!"));
      return;
    }

    // STEP 9 Verify origin is match with session
    if (!clientData.getString("origin").equals(options.getOrigin())) {
      handler.handle(Future.failedFuture("Origins don't match!"));
      return;
    }

    switch (clientData.getString("type")) {
      case "webauthn.create":
        try {
          final JsonObject result = verifyWebAuthNCreate(webauthnResp, clientDataJSON, clientData);
          // STEP 16 Save data to database
          if (result.getBoolean("verified", false)) {
            JsonObject authrInfo = result.getJsonObject("authrInfo");
            // the principal for vertx-auth
            JsonObject principal = new JsonObject()
              .put("credID", authrInfo.getString("credID"))
              .put("registered", true)
              .put("publicKey", authrInfo.getString("publicKey"))
              .put("counter", authrInfo.getLong("counter", 0L));

            store.updateUserCredential(username, principal, updateUserCredential -> {
              if (updateUserCredential.failed()) {
                handler.handle(Future.failedFuture(updateUserCredential.cause()));
              } else {
                handler.handle(Future.succeededFuture(new WebAuthNUser(principal)));
              }
            });
          } else {
            handler.handle(Future.failedFuture("Can not authenticate signature!"));
          }
        } catch (RuntimeException | IOException e) {
          handler.handle(Future.failedFuture(e));
        }
        return;
      case "webauthn.get":
        store.getUserCredentials(username, getUserCredentials -> {
          if (getUserCredentials.failed()) {
            handler.handle(Future.failedFuture(getUserCredentials.cause()));
          } else {
            List<JsonObject> authenticators = getUserCredentials.result();
            if (authenticators == null) {
              authenticators = Collections.emptyList();
            }

            // STEP 24 Query public key base on user ID
            JsonObject authenticator = findAuthr(webauthnResp.getString("id"), authenticators);

            if (authenticator == null) {
              handler.handle(Future.failedFuture("Cannot find an authenticator with id: " + webauthnResp.getString("id")));
              return;
            }

            try {
              final JsonObject result = verifyWebAuthNGet(webauthnResp, clientDataJSON, clientData, authenticator);

              if (result.getBoolean("verified", false)) {
                // update the counter on the authenticator
                authenticator.put("counter", result.getLong("counter", 0L));
                // update the credential (the important here is to update the counter)
                store.updateUserCredential(username, authenticator, updateUserCredential -> {
                  if (updateUserCredential.failed()) {
                    handler.handle(Future.failedFuture(updateUserCredential.cause()));
                    return;
                  }
                  handler.handle(Future.succeededFuture(new WebAuthNUser(result)));
                });
              } else {
                handler.handle(Future.failedFuture("Can not authenticate signature!"));
              }
            } catch (RuntimeException | IOException e) {
              handler.handle(Future.failedFuture(e));
            }
          }
        });
        return;
      default:
        handler.handle(Future.failedFuture("Can not determine type of response!"));
    }
  }

  /**
   * Verify creadentials from client
   *
   * @param webAuthnResponse - Data from navigator.credentials.create
   */
  private JsonObject verifyWebAuthNCreate(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject clientData) throws AttestationException, IOException {
    JsonObject response = webAuthnResponse.getJsonObject("response");
    // STEP 11 Extract attestation Object
    try (JsonParser parser = CBOR.cborParser(response.getString("attestationObject"))) {
      //      {
      //        "fmt": "fido-u2f",
      //        "authData": "cbor",
      //        "attStmt": {
      //          "sig": "cbor",
      //          "x5c": [
      //            "cbor"
      //          ]
      //        }
      //      }
      JsonObject ctapMakeCredResp = new JsonObject(CBOR.<Map>parse(parser));
      // STEP 12 Extract auth data
      AuthenticatorData authrDataStruct = new AuthenticatorData(ctapMakeCredResp.getString("authData"));
      // STEP 13 Extract public key
      byte[] publicKey = authrDataStruct.getCredentialPublicKey();

      response = new JsonObject()
        .put("verified", false);

      final String fmt = ctapMakeCredResp.getString("fmt");

      // STEP 14 Verify attestation based on type of device
      final Attestation attestation = attestations.get(fmt);

      if (attestation == null) {
        LOG.error("Unknown attestation fmt: " + fmt);
      } else {
        response
          .put("verified", attestation.verify(webAuthnResponse, clientDataJSON, ctapMakeCredResp, authrDataStruct));
      }

      if (response.getBoolean("verified")) {
        // STEP 15 Create data for save to database
        response.put("authrInfo", new JsonObject()
          .put("fmt", fmt)
          .put("publicKey", b64enc.encodeToString(publicKey))
          .put("counter", authrDataStruct.getSignCounter())
          .put("credID", b64enc.encodeToString(authrDataStruct.getCredentialId())));
      }

      return response;
    }
  }

  /**
   * @param webAuthnResponse - Data from navigator.credentials.get
   * @param authr   - Credential from Database
   */
  private JsonObject verifyWebAuthNGet(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject clientData, JsonObject authr) throws IOException {

    JsonObject response = webAuthnResponse.getJsonObject("response");

    // STEP 25 parse auth data
    byte[] authenticatorData = b64dec.decode(response.getString("authenticatorData"));
    AuthenticatorData authrDataStruct = new AuthenticatorData(authenticatorData);

    if (!authrDataStruct.is(AuthenticatorData.USER_PRESENT)) {
      throw new RuntimeException("User was NOT present durring authentication!");
    }

    // TODO: assert the algorithm to be SHA-256 clientData.getString("hashAlgorithm") ?
    // STEP 26 hash clientDataJSON with sha256
    byte[] clientDataHash = hash(clientDataJSON);
    // STEP 27 create signature base by concat authenticatorData and clientDataHash
    Buffer signatureBase = Buffer.buffer()
      .appendBytes(authenticatorData)
      .appendBytes(clientDataHash);

    // STEP 28 format public key
    try (JsonParser parser = CBOR.cborParser(authr.getString("publicKey"))) {
      // the decoded credential primary as a JWK
      JWK publicKey = COSE.toJWK(CBOR.parse(parser));

      // STEP 29 convert signature to buffer
      byte[] signature = b64dec.decode(response.getString("signature"));

      // STEP 30 verify signature
      boolean verified = publicKey.verify(signature, signatureBase.getBytes());

      // start building the response
      response = new JsonObject().put("verified", verified);

      if (verified) {
        if (authrDataStruct.getSignCounter() <= authr.getLong("counter")) {
          throw new RuntimeException("Authr counter did not increase!");
        }
        // update the counter
        response.put("counter", authrDataStruct.getSignCounter());
      }

      return response;
    }
  }

  /**
   * Takes an array of registered authenticators and find one specified by credID
   *
   * @param credID         - base64url encoded credential
   * @param authenticators - list of authenticators
   * @return found authenticator
   */
  private JsonObject findAuthr(String credID, List<JsonObject> authenticators) {
    for (JsonObject authr : authenticators) {
      if (credID.equals(authr.getValue("credID"))) {
        return authr;
      }
    }

    throw new RuntimeException("Unknown authenticator with credID: " + credID);
  }

  private byte[] hash(byte[] data) {
    synchronized (sha256) {
      sha256.update(data);
      return sha256.digest();
    }
  }
}
