package io.vertx.ext.auth.webauthn.impl;

import com.fasterxml.jackson.core.JsonParser;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthStore;
import io.vertx.ext.auth.HashingAlgorithm;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.webauthn.*;
import io.vertx.ext.auth.webauthn.impl.attestation.Attestation;
import io.vertx.ext.jwt.JWK;

import java.io.IOException;
import java.util.*;

public class WebAuthNImpl implements WebAuthN {

  private static final JsonObject EMPTY = new JsonObject(Collections.emptyMap());

  // codecs
  private final Base64.Encoder b64enc = Base64.getUrlEncoder().withoutPadding();
  private final Base64.Decoder b64dec = Base64.getUrlDecoder();

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
  }

  private String randomBase64URLBuffer(int length) {
    final byte[] buff = new byte[length];
    random.nextBytes(buff);
    return b64enc.encodeToString(buff);
  }

  @Override
  public WebAuthN generateServerCredentialsChallenge(JsonObject user, CredentialsChallengeType type, Handler<AsyncResult<JsonObject>> handler) {

    store.getUserCredentials(user.getString("username"), getUserCredentials -> {
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

        handler.handle(Future.succeededFuture(
          new JsonObject()
            .put("challenge", randomBase64URLBuffer(32))
            .put("rp", new JsonObject()
              .put("name", options.getRealm()))
            .put("user", user.copy().put("id", id))
              .put("authenticatorSelection", authenticatorSelection)
              .put("attestation", "direct")
              .put("pubKeyCredParams", new JsonArray()
                .add(new JsonObject()
                  .put("type", "public-key")
                  .put("alg", -7)))));
      }
    });

    return this;
  }

  @Override
  public WebAuthN generateServerGetAssertion(String username, Handler<AsyncResult<JsonObject>> handler) {

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

      // STEP 19 Return allow credential ID
      for (JsonObject cred : credentials) {
        String credId = cred.getString("credID");
        if (credId != null) {
          allowCredentials
            .add(new JsonObject()
              .put("type", "public-key")
              .put("id", credId)
              .put("transports", new JsonArray(options.getTransports())));
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
    final String username = Objects.requireNonNull(authInfo.getUsername());
    final JsonObject webauthnResp = Objects.requireNonNull(authInfo.getWebauthn());

    final JsonObject response = webauthnResp.getJsonObject("response", EMPTY);

    JsonObject clientData = new JsonObject(Buffer.buffer(b64dec.decode(response.getString("clientDataJSON"))));

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
          final JsonObject result = verifyWebAuthNCreate(webauthnResp);
          // STEP 16 Save data to database
          if (result.getBoolean("verified", false)) {
            JsonObject authrInfo = result.getJsonObject("authrInfo");

            store.updateUserCredential(
              username,
              new JsonObject()
                .put("credID", authrInfo.getString("credID"))
                .put("registered", true)
                .put("public-key", authrInfo.getString("public-key"))
                .put("counter", authrInfo.getLong("counter")),
              updateUserCredential -> {
                if (updateUserCredential.failed()) {
                  handler.handle(Future.failedFuture(updateUserCredential.cause()));
                } else {
                  handler.handle(Future.succeededFuture(new WebAuthNUser(result)));
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

            try {
              final JsonObject result = verifyWebAuthNGet(webauthnResp, authenticators);

              if (result.getBoolean("verified", false)) {
                handler.handle(Future.succeededFuture(new WebAuthNUser(result)));
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
  private JsonObject verifyWebAuthNCreate(JsonObject webAuthnResponse) throws IOException {

    JsonObject response = webAuthnResponse.getJsonObject("response", EMPTY);
    // STEP 11 Extract attestation Object
    try (JsonParser parser = CBOR.cborParser(response.getString("attestationObject"))) {
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

      if (attestation != null) {
        response
          .put("verified", attestation.verify(webAuthnResponse, ctapMakeCredResp, authrDataStruct));
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
   * @param authenticators   - Credential from Database
   */
  private JsonObject verifyWebAuthNGet(JsonObject webAuthnResponse, List<JsonObject> authenticators) throws IOException {

    // STEP 24 Query public key base on user ID
    JsonObject authr = findAuthr(webAuthnResponse.getString("id"), authenticators);

    JsonObject response = webAuthnResponse.getJsonObject("response", EMPTY);

    byte[] clientDataJSON = b64dec.decode(response.getString("clientDataJSON"));

    JsonObject clientData = new JsonObject(Buffer.buffer(clientDataJSON));

    // STEP 25 parse auth data
    byte[] authenticatorData = b64dec.decode(response.getString("authenticatorData"));
    AuthenticatorData authrDataStruct = new AuthenticatorData(authenticatorData);

    if (!authrDataStruct.is(AuthenticatorData.USER_PRESENT)) {
      throw new RuntimeException("User was NOT present durring authentication!");
    }
    // STEP 26 hash clientDataJSON with sha256
    byte[] clientDataHash = hash(clientData.getString("hashAlgorithm"), clientDataJSON);
    // STEP 27 create signature base by concat authenticatorData and clientDataHash
    Buffer signatureBase = Buffer.buffer()
      .appendBytes(authenticatorData)
      .appendBytes(clientDataHash);

    // STEP 28 format public key
    try (JsonParser parser = CBOR.cborParser(authr.getString("public-key"))) {
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

  private byte[] hash(String alg, byte[] data) {
    // TODO error handling
    return HashingAlgorithm.getByAlgorithm(alg).hash(data);
  }
}
