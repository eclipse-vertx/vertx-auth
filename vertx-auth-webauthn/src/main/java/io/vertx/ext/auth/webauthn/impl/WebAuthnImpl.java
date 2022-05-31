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
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.impl.cose.CWK;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.webauthn.*;
import io.vertx.ext.auth.webauthn.impl.attestation.Attestation;
import io.vertx.ext.auth.webauthn.impl.attestation.AttestationException;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataServiceImpl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;

import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;
import static io.vertx.ext.auth.impl.Codec.base64UrlEncode;
import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.hash;

public class WebAuthnImpl implements WebAuthn {

  private static final Logger LOG = LoggerFactory.getLogger(WebAuthn.class);

  private final Map<String, Attestation> attestations = new HashMap<>();

  private final VertxContextPRNG random;
  private final WebAuthnOptions options;
  private final MetaDataServiceImpl mds;

  private Function<Authenticator, Future<List<Authenticator>>> fetcher = authr -> Future.failedFuture("Fetcher function not available");
  private Function<Authenticator, Future<Void>> updater = authr -> Future.failedFuture("Updater function not available");

  public WebAuthnImpl(Vertx vertx, WebAuthnOptions options) {
    random = VertxContextPRNG.current(vertx);
    this.options = options;

    if (options == null) {
      throw new IllegalArgumentException("options cannot be null!");
    }

    // verify that RP is not null
    if (options.getRelyingParty() == null) {
      throw new IllegalArgumentException("options.relyingParty cannot be null!");
    }

    // verify that RP.name is not null
    if (options.getRelyingParty().getName() == null) {
      throw new IllegalArgumentException("options.relyingParty.name cannot be null!");
    }

    this.mds = new MetaDataServiceImpl(vertx, options);
    ServiceLoader<Attestation> attestationServiceLoader = ServiceLoader.load(Attestation.class);

    for (Attestation att : attestationServiceLoader) {
      attestations.put(att.fmt(), att);
    }
  }

  private String randomBase64URLBuffer(int length) {
    final byte[] buff = new byte[length];
    random.nextBytes(buff);
    return base64UrlEncode(buff);
  }

  private void putOpt(JsonObject json, String key, Object value) {
    if (value != null) {
      if (value instanceof Enum<?>) {
        json.put(key, value.toString());
        return;
      }
      if (value instanceof JsonObject) {
        if (((JsonObject) value).isEmpty()) {
          return;
        }
      }
      if (value instanceof JsonArray) {
        if (((JsonArray) value).isEmpty()) {
          return;
        }
      }
      json.put(key, value);
    }
  }

  private void addOpt(JsonArray json, Object value) {
    if (value != null) {
      if (value instanceof Enum<?>) {
        json.add(value.toString());
        return;
      }
      if (value instanceof JsonObject) {
        if (((JsonObject) value).isEmpty()) {
          return;
        }
      }
      if (value instanceof JsonArray) {
        if (((JsonArray) value).isEmpty()) {
          return;
        }
      }
      json.add(value);
    }
  }

  private static String uUIDtoBase64Url(UUID uuid) {
    Buffer buffer = Buffer.buffer(16);
    buffer.setLong(0, uuid.getMostSignificantBits());
    buffer.setLong(8, uuid.getLeastSignificantBits());
    return base64UrlEncode(buffer.getBytes());
  }

  @Override
  public WebAuthn authenticatorFetcher(Function<Authenticator, Future<List<Authenticator>>> fetcher) {
    if (fetcher == null) {
      throw new IllegalArgumentException("Function cannot be null");
    }
    this.fetcher = fetcher;
    return this;
  }

  @Override
  public WebAuthn authenticatorUpdater(Function<Authenticator, Future<Void>> updater) {
    if (updater == null) {
      throw new IllegalArgumentException("Function cannot be null");
    }
    this.updater = updater;
    return this;
  }

  @Override
  public Future<JsonObject> createCredentialsOptions(JsonObject user) {

    return fetcher
      .apply(new Authenticator().setUserName(user.getString("name")))
      .map(authenticators -> {
        // empty structure with all required fields
        JsonObject json = new JsonObject()
          .put("rp", new JsonObject())
          .put("user", new JsonObject())
          .put("challenge", randomBase64URLBuffer(options.getChallengeLength()))
          .put("pubKeyCredParams", new JsonArray())
          .put("authenticatorSelection", new JsonObject());

        // put non null values for RelyingParty
        putOpt(json.getJsonObject("rp"), "id", options.getRelyingParty().getId());
        putOpt(json.getJsonObject("rp"), "name", options.getRelyingParty().getName());
        putOpt(json.getJsonObject("rp"), "icon", options.getRelyingParty().getIcon());

        // put non null values for User
        putOpt(json.getJsonObject("user"), "id", uUIDtoBase64Url(UUID.randomUUID()));
        putOpt(json.getJsonObject("user"), "name", user.getString("name"));
        putOpt(json.getJsonObject("user"), "displayName", user.getString("displayName"));
        putOpt(json.getJsonObject("user"), "icon", user.getString("icon"));
        // put the public key credentials parameters
        for (PublicKeyCredential pubKeyCredParam : options.getPubKeyCredParams()) {
          addOpt(
            json.getJsonArray("pubKeyCredParams"),
            new JsonObject()
              .put("alg", pubKeyCredParam.coseId())
              .put("type", "public-key"));
        }
        // optional timeout
        putOpt(json, "timeout", options.getTimeout());
        // optional excluded credentials
        if (!authenticators.isEmpty()) {
          JsonArray transports = new JsonArray();

          for (AuthenticatorTransport transport : options.getTransports()) {
            addOpt(transports, transport.toString());
          }

          JsonArray excludeCredentials = new JsonArray();
          for (Authenticator key : authenticators) {
            JsonObject credentialDescriptor = new JsonObject()
              .put("type", key.getType())
              .put("id", key.getCredID());
            // add optional transports to the descriptor
            putOpt(credentialDescriptor, "transports", transports);
            // add to the excludeCredentials list
            addOpt(excludeCredentials, credentialDescriptor);
          }
          // add the the response json
          putOpt(json, "excludeCredentials", excludeCredentials);
        }
        // optional authenticator selection
        putOpt(json.getJsonObject("authenticatorSelection"), "requireResidentKey", options.getRequireResidentKey());
        putOpt(json.getJsonObject("authenticatorSelection"), "authenticatorAttachment", options.getAuthenticatorAttachment());
        putOpt(json.getJsonObject("authenticatorSelection"), "userVerification", options.getUserVerification());
        // optional attestation
        putOpt(json, "attestation", options.getAttestation());
        // optional extensions
        putOpt(json, "extensions", options.getExtensions());

        return json;
      });
  }

  @Override
  public Future<JsonObject> getCredentialsOptions(String name) {

    // https://w3c.github.io/webauthn/#dictionary-assertion-options
    JsonObject json = new JsonObject()
      .put("challenge", randomBase64URLBuffer(options.getChallengeLength()));
    putOpt(json, "timeout", options.getTimeout());
    putOpt(json, "rpId", options.getRelyingParty().getId());
    putOpt(json, "userVerification", options.getUserVerification());
    putOpt(json, "extensions", options.getExtensions());

    // we allow Resident Credentials or (RK) requests
    // this means that name is not required
    if (options.getRequireResidentKey()) {
      if (name == null) {
        return Future.succeededFuture(json);
      }
    }

    // fallback to non RK requests
    return fetcher
      .apply(new Authenticator().setUserName(name))
      .compose(authenticators -> {
        if (authenticators.isEmpty()) {
          // fail as the user has never register an authenticator
          return Future.failedFuture("No authenticators registered for user: " + name);
        }
        // there are authenticators, continue...
        return Future.succeededFuture(authenticators);
      })
      .map(authenticators -> {
        JsonArray allowCredentials = new JsonArray();

        JsonArray transports = new JsonArray();
        if (options.getTransports() != null) {
          for (AuthenticatorTransport transport : options.getTransports()) {
            transports.add(transport.toString());
          }
        }

        for (Authenticator key : authenticators) {
          String credId = key.getCredID();
          if (credId != null) {
            JsonObject credential = new JsonObject()
              .put("type", "public-key")
              .put("id", credId);
            putOpt(credential, "transports", transports);

            allowCredentials.add(credential);
          }
        }
        putOpt(json, "allowCredentials", allowCredentials);

        return json;
      });
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
      final byte[] clientDataJSON = base64UrlDecode(webauthn.getJsonObject("response").getString("clientDataJSON"));
      JsonObject clientData = new JsonObject(Buffer.buffer(clientDataJSON));

      // Step #2
      // Verify challenge is match with session
      if (!authInfo.getChallenge().equals(clientData.getString("challenge"))) {
        handler.handle(Future.failedFuture("Challenges don't match!"));
        return;
      }

      // Step #3
      // If the auth info object contains an Origin we can verify it:
      if (authInfo.getOrigin() != null) {
        if (!authInfo.getOrigin().equals(clientData.getString("origin"))) {
          handler.handle(Future.failedFuture("Origins don't match!"));
          return;
        }
      }

      // optional data
      if (clientData.containsKey("tokenBinding")) {
        JsonObject tokenBinding = clientData.getJsonObject("tokenBinding");
        if (tokenBinding == null) {
          handler.handle(Future.failedFuture("Invalid clientDataJSON.tokenBinding"));
          return;
        }
        // in this case we need to check the status
        switch (tokenBinding.getString("status")) {
          case "present":
          case "supported":
          case "not-supported":
            // OK
            break;
          default:
            handler.handle(Future.failedFuture("Invalid clientDataJSON.tokenBinding.status"));
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
            final Authenticator authrInfo = verifyWebAuthNCreate(authInfo, clientDataJSON);
            // by default the store can upsert if a credential is missing, the user has been verified so it is valid
            // the store however might disallow this operation
            authrInfo.setUserName(username);

            // the create challenge is complete we can finally safe this
            // new authenticator to the storage
            updater.apply(authrInfo)
              .onFailure(err -> handler.handle(Future.failedFuture(err)))
              .onSuccess(stored -> handler.handle(Future.succeededFuture(User.create(authrInfo.toJson()))));

          } catch (RuntimeException | AttestationException | IOException | NoSuchAlgorithmException e) {
            handler.handle(Future.failedFuture(e));
          }
          return;
        case "webauthn.get":
          Authenticator query = new Authenticator();
          if (options.getRequireResidentKey()) {
            // username are not provided (RK) we now need to lookup by id
            query.setCredID(webauthn.getString("id"));
          } else {
            // username can't be null
            if (username == null) {
              handler.handle(Future.failedFuture("username can't be null!"));
              return;
            }
            query.setUserName(username);
          }

          fetcher.apply(query)
            .onFailure(err -> handler.handle(Future.failedFuture(err)))
            .onSuccess(authenticators -> {
              if (authenticators == null) {
                authenticators = Collections.emptyList();
              }
              // As we can get here with or without a username the size of the authenticator
              // list is unbounded.
              // This means that we **must** lookup the list for the right authenticator
              for (Authenticator authenticator : authenticators) {
                if (webauthn.getString("id").equals(authenticator.getCredID())) {
                  try {
                    final long counter = verifyWebAuthNGet(authInfo, clientDataJSON, authenticator.toJson());
                    // update the counter on the authenticator
                    authenticator.setCounter(counter);
                    // update the credential (the important here is to update the counter)
                    updater.apply(authenticator)
                      .onFailure(err -> handler.handle(Future.failedFuture(err)))
                      .onSuccess(stored -> handler.handle(Future.succeededFuture(User.create(authenticator.toJson()))));

                  } catch (RuntimeException | AttestationException | IOException | NoSuchAlgorithmException e) {
                    handler.handle(Future.failedFuture(e));
                  }
                  return;
                }
              }
              // No valid authenticator was found
              handler.handle(Future.failedFuture("Cannot find authenticator with id: " + webauthn.getString("id")));
            });

          return;
        default:
          handler.handle(Future.failedFuture("Can not determine type of response!"));
      }
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
    }
  }

  /**
   * Verify credentials creation from client
   *
   * @param request        - The request as received by the {@link #authenticate(Credentials, Handler)} method.
   * @param clientDataJSON - Binary session data
   */
  private Authenticator verifyWebAuthNCreate(WebAuthnCredentials request, byte[] clientDataJSON) throws AttestationException, IOException, NoSuchAlgorithmException {
    JsonObject response = request.getWebauthn().getJsonObject("response");
    if (!response.containsKey("attestationObject")) {
      throw new AttestationException("Missing response.attestationObject");
    }
    // Extract attestation Object
    try (CBOR decoder = new CBOR(base64UrlDecode(response.getString("attestationObject")))) {
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
      JsonObject attestation = new JsonObject(decoder.<Map<String, Object>>readObject());

      // Step #5
      // Extract and parse auth data
      AuthData authData = new AuthData(base64UrlDecode(attestation.getString("authData")));
      // One extra check, we can verify that the relying party id is for the given domain
      if (request.getDomain() != null) {
        if (!MessageDigest.isEqual(authData.getRpIdHash(), hash("SHA-256", request.getDomain().getBytes(StandardCharsets.UTF_8)))) {
          throw new AttestationException("WebAuthn rpIdHash invalid (the domain does not match the AuthData)");
        }
      }

      // Step #6
      // check that the user was either validated or present
      switch (options.getUserVerification()) {
        case REQUIRED:
          if (!authData.is(AuthData.USER_VERIFIED) && !authData.is(AuthData.USER_PRESENT)) {
            throw new AttestationException("User was either not verified or present during credentials creation");
          }
          break;
        case PREFERRED:
          if (!authData.is(AuthData.USER_VERIFIED) && !authData.is(AuthData.USER_PRESENT)) {
            LOG.warn("User was either not verified or present during credentials creation");
          }
          break;
        case DISCOURAGED:
          if (authData.is(AuthData.USER_VERIFIED) || authData.is(AuthData.USER_PRESENT)) {
            LOG.info("User was either verified or present during credentials creation");
          }
          break;
      }

      // From here we start really verifying the create challenge:

      // STEP webauthn.create#1
      // Verify attestation:
      // the "fmt" informs what kind of attestation is present
      final String fmt = attestation.getString("fmt");
      // we lookup the loaded attestations at creation of this object
      // we don't look everytime to avoid a performance penalty
      final Attestation verifier = attestations.get(fmt);
      final AttestationCertificates certificates;

      // If there's no verifier then a extra implementation is required...
      if (verifier == null) {
        throw new AttestationException("Unknown attestation fmt: " + fmt);
      } else {
        // If the authenticator data has no attestation data,
        // the we can't really attest anything
        if (!authData.is(AuthData.ATTESTATION_DATA)) {
          throw new AttestationException("WebAuthn response does not contain attestation data!");
        }
        // invoke the right verifier
        // well known verifiers are:
        // * none
        // * fido-u2f
        // * android-safetynet
        // * android-key
        // * packed
        // * tpm
        // * apple
        certificates = verifier
          .validate(options, mds.metadata(), clientDataJSON, attestation, authData);
      }

      // STEP webauthn.create#2
      // Create new authenticator record and store counter, credId and publicKey in the DB
      return new Authenticator()
        .setFmt(fmt)
        .setAaguid(authData.getAaguidString())
        .setPublicKey(base64UrlEncode(authData.getCredentialPublicKey()))
        .setCounter(authData.getSignCounter())
        .setCredID(base64UrlEncode(authData.getCredentialId()))
        .setAttestationCertificates(certificates);
    }
  }

  /**
   * Verify navigator.credentials.get response
   *
   * @param request        - The request as received by the {@link #authenticate(Credentials, Handler)} method.
   * @param clientDataJSON - The extracted clientDataJSON
   * @param credential     - Credential from Database
   */
  private long verifyWebAuthNGet(WebAuthnCredentials request, byte[] clientDataJSON, JsonObject credential) throws IOException, AttestationException, NoSuchAlgorithmException {

    JsonObject response = request.getWebauthn().getJsonObject("response");

    // Step #5
    // parse auth data
    byte[] authenticatorData = base64UrlDecode(response.getString("authenticatorData"));
    AuthData authData = new AuthData(authenticatorData);
    // One extra check, we can verify that the relying party id is for the given domain
    if (request.getDomain() != null) {
      if (!MessageDigest.isEqual(authData.getRpIdHash(), hash("SHA-256", request.getDomain().getBytes(StandardCharsets.UTF_8)))) {
        throw new AttestationException("WebAuthn rpIdHash invalid (the domain does not match the AuthData)");
      }
    }

    // Step #6
    // check that the user was either validated or present
    switch (options.getUserVerification()) {
      case REQUIRED:
        if (!authData.is(AuthData.USER_VERIFIED) || !authData.is(AuthData.USER_PRESENT)) {
          throw new AttestationException("User was either not verified or not present during credentials creation");
        }
        break;
      case PREFERRED:
        if (!authData.is(AuthData.USER_VERIFIED) && !authData.is(AuthData.USER_PRESENT)) {
          LOG.warn("User was either not verified or present during credentials creation");
        }
        break;
      case DISCOURAGED:
        if (authData.is(AuthData.USER_VERIFIED) || authData.is(AuthData.USER_PRESENT)) {
          LOG.info("User was either verified or present during credentials creation");
        }
        break;
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
    try (CBOR decoder = new CBOR(base64UrlDecode(credential.getString("publicKey")))) {
      // the decoded credential primary as a JWK
      JWK publicKey = CWK.toJWK(new JsonObject(decoder.<Map<String, Object>>readObject()));
      // convert signature to buffer
      byte[] signature = base64UrlDecode(response.getString("signature"));
      // verify signature
      JWS jws = new JWS(publicKey);
      if (!jws.verify(signature, signatureBase.getBytes())) {
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
        if (authData.getSignCounter() != 0 && authData.getSignCounter() <= credential.getLong("counter", 0L)) {
          throw new AttestationException("Authenticator counter did not increase!");
        }
      }

      // Step webauthn.get#7
      // Update counter value in database
      // return the counter so it can be updated on the store
      return authData.getSignCounter();
    }
  }

  /**
   * Internal API not fully ready for prime time
   */
  @Override
  public MetaDataService metaDataService() {
    return mds;
  }
}
