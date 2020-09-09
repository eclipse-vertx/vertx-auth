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
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.VertxContextPRNG;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.impl.UserImpl;
import io.vertx.ext.auth.impl.cose.CWK;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.webauthn.*;
import io.vertx.ext.auth.webauthn.impl.attestation.Attestation;
import io.vertx.ext.auth.webauthn.impl.attestation.AttestationException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.hash;

public class WebAuthnImpl implements WebAuthn {

  private static final Logger LOG = LoggerFactory.getLogger(WebAuthn.class);

  private final VertxContextPRNG random;
  private final WebAuthnOptions options;
  private final CredentialStore store;

  private final Map<String, Attestation> attestations = new HashMap<>();

  public WebAuthnImpl(Vertx vertx, WebAuthnOptions options, CredentialStore store) {
    random = VertxContextPRNG.current(vertx);

    this.options = options;
    this.store = store;

    if (options == null || store == null) {
      throw new IllegalArgumentException("options and store cannot be null!");
    }

    ServiceLoader<Attestation> attestationServiceLoader = ServiceLoader.load(Attestation.class);

    for (Attestation att : attestationServiceLoader) {
      attestations.put(att.fmt(), att);
    }
  }

  private byte[] randomBase64URLBuffer(int length) {
    final byte[] buff = new byte[length];
    random.nextBytes(buff);
    return buff;
  }

  private void putOpt(JsonObject json, String key, Object value) {
    if (value != null) {
      if (value instanceof Enum<?>) {
        json.put(key, value.toString());
        return;
      }
      if (value instanceof Number) {
        if (((Number) value).intValue() != 0) {
          json.put(key, value.toString());
        }
        return;
      }
      json.put(key, value);
    }
  }

  @Override
  public WebAuthn createCredentialsOptions(JsonObject user, Handler<AsyncResult<JsonObject>> handler) {

    store.getUserCredentialsByName(user.getString("name"), getUserCredentials -> {
      if (getUserCredentials.failed()) {
        handler.handle(Future.failedFuture(getUserCredentials.cause()));
        return;
      }

      List<JsonObject> credentials = getUserCredentials.result();

      if (credentials == null || credentials.size() == 0) {
        // generate a new ID for this new potential user
        final String id = store.generateId();

        final JsonArray pubKeyCredParams = new JsonArray();

        for (PublicKeyCredential pubKeyCredParam : options.getPubKeyCredParams()) {
          pubKeyCredParams.add(pubKeyCredParam.toJson());
        }

        // user configuration
        final JsonObject _user = new JsonObject()
          .put("id", id)
          .put("name", user.getString("name"))
          .put("displayName", user.getString("displayName"));

        if (user.getString("icon") != null) {
          _user.put("icon", user.getString("icon"));
        }

        // authenticatorSelection configuration
        final JsonObject authenticatorSelection = options.getAuthenticatorSelection();

        // final assembly
        final JsonObject publicKey = new JsonObject()
          .put("challenge", randomBase64URLBuffer(options.getChallengeLength()))
          .put("rp", options.getRelayParty().toJson())
          .put("user", _user)
          .put("pubKeyCredParams", pubKeyCredParams);

        if (authenticatorSelection != null) {
          publicKey.put("authenticatorSelection", authenticatorSelection);
        }

        if (options.getAttestation() != null) {
          publicKey.put("attestation", options.getAttestation().toString());
        }
        if (options.getTimeout() > 0) {
          publicKey.put("timeout", options.getTimeout());
        }

        handler.handle(Future.succeededFuture(publicKey));
      } else {
        handler.handle(Future.failedFuture("User exists!"));
      }
    });

    return this;
  }

  @Override
  public WebAuthn getCredentialsOptions(String username, Handler<AsyncResult<JsonObject>> handler) {

    // we allow Resident Credentials or (RK) requests
    // this means that username is not required
    if (options.getRequireResidentKey()) {
      if (username == null) {
        handler.handle(Future.succeededFuture(
          new JsonObject()
            .put("challenge", randomBase64URLBuffer(options.getChallengeLength()))));
        return this;
      }
    }

    // fallback to non RK requests

    store.getUserCredentialsByName(username, getUserCredentials -> {
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

      for (AuthenticatorTransport transport : options.getTransports()) {
        transports.add(transport.toString());
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
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> handler) {
    authenticate(new WebAuthnCredentials(authInfo), handler);
  }

  @Override
  public void authenticate(Credentials credentials, Handler<AsyncResult<User>> handler) {
    try {
      // cast
      WebAuthnCredentials authInfo = (WebAuthnCredentials) credentials;
      // check
      authInfo.checkValid(null);
      // The basic data supplied with any kind of validation is:
      //    {
      //      "rawId": "base64url",
      //      "id": "base64url",
      //      "response": {
      //        "clientDataJSON": "base64url"
      //      }
      //    }
      final JsonObject webauthn = authInfo.getWebauthn();

      // verifying the webauthn response starts here:

      // regardless of the request the first 6 steps are always executed:

      // 1. Decode ClientDataJSON
      // 2. Check that challenge is set to the challenge you’ve sent
      // 3. Check that origin is set to the the origin of your website. If it’s not raise the alarm, and log the event, because someone tried to phish your user
      // 4. Check that type is set to either “webauthn.create” or “webauthn.get”.
      // 5. Parse authData or authenticatorData.
      // 6. Check that flags have UV or UP flags set.

      // STEP #1
      // The client data (or session) is a base64 url encoded JSON
      // we specifically keep track of the binary representation as it will be
      // used later on during validation to verify signatures for tampering
      final byte[] clientDataJSON = webauthn.getJsonObject("response").getBinary("clientDataJSON");
      JsonObject clientData = new JsonObject(Buffer.buffer(clientDataJSON));

      // Step #2
      // Verify challenge is match with session
      if (!clientData.getString("challenge").equals(authInfo.getChallenge())) {
        handler.handle(Future.failedFuture("Challenges don't match!"));
        return;
      }

      // Step #3
      // If the auth info object contains an Origin we can verify it:
      if (authInfo.getOrigin() != null) {
        if (!clientData.getString("origin").equals(authInfo.getOrigin())) {
          handler.handle(Future.failedFuture("Origins don't match!"));
          return;
        }
      }

      final String username = authInfo.getUsername();

      // Step #4
      // Verify that the type is valid and that is "webauthn.create" or "webauthn.get"
      if (!clientData.containsKey("type")) {
        handler.handle(Future.failedFuture("Missing type on client data"));
        return;
      }

      switch (clientData.getString("type")) {
        case "webauthn.create":
          // we always need a username to register
          if (username == null) {
            handler.handle(Future.failedFuture("username can't be null!"));
            return;
          }

          try {
            final JsonObject authrInfo = verifyWebAuthNCreate(authInfo, clientDataJSON);
            // the principal for vertx-auth
            JsonObject principal = new JsonObject()
              .put("credID", authrInfo.getString("credID"))
              .put("publicKey", authrInfo.getString("publicKey"))
              .put("counter", authrInfo.getLong("counter", 0L));

            // by default the store can upsert if a credential is missing, the user has been verified so it is valid
            // the store however might dissallow this operation
            JsonObject storeItem = new JsonObject()
              .mergeIn(principal)
              .put("username", username);

            store.updateUserCredential(authrInfo.getString("credID"), storeItem, true, updateUserCredential -> {
              if (updateUserCredential.failed()) {
                handler.handle(Future.failedFuture(updateUserCredential.cause()));
              } else {
                handler.handle(Future.succeededFuture(new UserImpl(principal)));
              }
            });
          } catch (RuntimeException | IOException | NoSuchAlgorithmException e) {
            handler.handle(Future.failedFuture(e));
          }
          return;
        case "webauthn.get":

          final Handler<AsyncResult<List<JsonObject>>> onGetUserCredentialsByAny = getUserCredentials -> {
            if (getUserCredentials.failed()) {
              handler.handle(Future.failedFuture(getUserCredentials.cause()));
            } else {
              List<JsonObject> authenticators = getUserCredentials.result();
              if (authenticators == null) {
                authenticators = Collections.emptyList();
              }

              // STEP 24 Query public key base on user ID
              Optional<JsonObject> authenticator = authenticators.stream()
                .filter(authr -> webauthn.getString("id").equals(authr.getValue("credID")))
                .findFirst();

              if (!authenticator.isPresent()) {
                handler.handle(Future.failedFuture("Cannot find an authenticator with id: " + webauthn.getString("rawId")));
                return;
              }

              try {
                final JsonObject json = authenticator.get();
                final long counter = verifyWebAuthNGet(webauthn, clientDataJSON, clientData, json);
                // update the counter on the authenticator
                json.put("counter", counter);
                // update the credential (the important here is to update the counter)
                store.updateUserCredential(webauthn.getString("rawId"), json, false, updateUserCredential -> {
                  if (updateUserCredential.failed()) {
                    handler.handle(Future.failedFuture(updateUserCredential.cause()));
                    return;
                  }
                  handler.handle(Future.succeededFuture(new UserImpl(json)));
                });
              } catch (RuntimeException | IOException | NoSuchAlgorithmException e) {
                handler.handle(Future.failedFuture(e));
              }
            }
          };

          if (options.getRequireResidentKey()) {
            // username are not provided (RK) we now need to lookup by rawId
            store.getUserCredentialsById(webauthn.getString("rawId"), onGetUserCredentialsByAny);

          } else {
            // username can't be null
            if (username == null) {
              handler.handle(Future.failedFuture("username can't be null!"));
              return;
            }
            store.getUserCredentialsByName(username, onGetUserCredentialsByAny);
          }

          return;
        default:
          handler.handle(Future.failedFuture("Can not determine type of response!"));
      }
    } catch (ClassCastException | CredentialValidationException e) {
      handler.handle(Future.failedFuture(e));
    }
  }

  /**
   * Verify credentials creation from client
   *
   * @param request        - The request as received by the {@link #authenticate(Credentials, Handler)} method.
   * @param clientDataJSON - Binary session data
   */
  private JsonObject verifyWebAuthNCreate(WebAuthnCredentials request, byte[] clientDataJSON) throws AttestationException, IOException, NoSuchAlgorithmException {
    JsonObject response = request.getWebauthn().getJsonObject("response");
    // Extract attestation Object
    try (JsonParser parser = CBOR.cborParser(response.getString("attestationObject"))) {
      //      {
      //        "fmt": "string",
      //        "authData": "cbor",
      //        "attStmt": {
      //          "sig": "base64",
      //          "x5c": [
      //            "base64"
      //          ]
      //        }
      //      }
      JsonObject attestation = new JsonObject(CBOR.<Map<String, Object>>parse(parser));

      // Step #5
      // Extract and parse auth data
      AuthData authData = new AuthData(attestation.getBinary("authData"));

      // Step #6
      // check that the user was either validated or present
      if (!authData.is(AuthData.USER_VERIFIED) && !authData.is(AuthData.USER_PRESENT)) {
        throw new AttestationException("User was either not verified or present during credentials creation");
      }

      // STEP 13 Extract public key
      byte[] publicKey = authData.getCredentialPublicKey();

      final String fmt = attestation.getString("fmt");

      // STEP 14 Verify attestation based on type of device
      final Attestation verifier = attestations.get(fmt);

      if (verifier == null) {
        throw new AttestationException("Unknown attestation fmt: " + fmt);
      } else {
        // perform the verification
        if (!authData.is(AuthData.ATTESTATION_DATA)) {
          throw new AttestationException("WebAuthn response does not contain attestation data!");
        }

        if (request.getDomain() != null) {
          if (!MessageDigest.isEqual(authData.getRpIdHash(), hash("SHA-256", request.getDomain().getBytes(StandardCharsets.UTF_8)))) {
            throw new AttestationException("WebAuthn rpIdHash invalid (the domain does not match the AuthData)");
          }
        }

        verifier
          .validate(request.getWebauthn(), clientDataJSON, attestation, authData);
      }

      // STEP 15 Create data for save to database
      return new JsonObject()
        .put("fmt", fmt)
        .put("publicKey", publicKey)
        .put("counter", authData.getSignCounter())
        .put("credID", authData.getCredentialId());
    }
  }

  /**
   * Verify navigator.credentials.get response
   *
   * @param webauthn   - Data from navigator.credentials.get
   * @param credential - Credential from Database
   */
  private long verifyWebAuthNGet(JsonObject webauthn, byte[] clientDataJSON, JsonObject clientData, JsonObject credential) throws IOException, AttestationException, NoSuchAlgorithmException {

    JsonObject response = webauthn.getJsonObject("response");

    // Step #5
    // parse auth data
    byte[] authenticatorData = response.getBinary("authenticatorData");
    AuthData authData = new AuthData(authenticatorData);

    // Step #6
    // check that the user was either validated or present
    if (!authData.is(AuthData.USER_VERIFIED) && !authData.is(AuthData.USER_PRESENT)) {
      throw new AttestationException("User was either not verified or present during credentials creation");
    }

    // From here we start the validation that is specific for webauthn.get

    // Step webauthn.get#1
    // hash clientDataJSON with SHA-256
    byte[] clientDataHash = hash("SHA-256", clientDataJSON);

    // Step webauthn.get#2
    // concat authenticatorData and clientDataHash
    Buffer signatureBase = Buffer.buffer()
      .appendBytes(authenticatorData)
      .appendBytes(clientDataHash);

    // Step webauthn.get#3
    // Using previously saved public key, verify signature over signatureBase.
    try (JsonParser parser = CBOR.cborParser(credential.getString("publicKey"))) {
      // the decoded credential primary as a JWK
      JWK publicKey = CWK.toJWK(new JsonObject(CBOR.<Map<String, Object>>parse(parser)));
      // convert signature to buffer
      byte[] signature = response.getBinary("signature");
      // verify signature
      if (!publicKey.verify(signature, signatureBase.getBytes())) {
        // Step webauthn.get#4
        // If you can’t verify signature multiple times, potentially raise the
        // alarm as phishing attempt most likely is occurring.
        LOG.warn("Failed to verify signature for key: " + credential.getString("publicKey"));
        throw new AttestationException("Failed to verify the signature!");
      }

      // Step webauthn.get#5
      // If counter in DB is 0, and response counter is 0, then authData does not support counter,
      // and this step should be skipped
      if (authData.getSignCounter() != 0 || credential.getLong("counter") != 0) {
        // Step webauthn.get#6
        // If response counter is not 0, check that it’s bigger than stored counter.
        // If it’s not, potentially raise the alarm as replay attack may have occurred.
        if (authData.getSignCounter() != 0 && authData.getSignCounter() < credential.getLong("counter")) {
          throw new AttestationException("Authenticator counter did not increase!");
        }
      }

      // Step webauthn.get#7
      // Update counter value in database
      // return the counter so it can be updated on the store
      return authData.getSignCounter();
    }
  }
}
