package io.vertx.ext.auth.webauthn.impl;

import com.fasterxml.jackson.core.JsonParser;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.webauthn.*;
import io.vertx.ext.jwt.JWK;

import java.io.IOException;
import java.security.*;
import java.util.*;

public class WebAuthNImpl implements WebAuthN {

  private static final JsonObject EMPTY = new JsonObject(Collections.emptyMap());

  // codecs
  private final Base64.Encoder b64enc = Base64.getUrlEncoder().withoutPadding();
  private final Base64.Decoder b64dec = Base64.getUrlDecoder();

  private final PRNG random;
  private final WebAuthNOptions options;
  private final MessageDigest sha256;

  private final Map<String, Attestation> attestations = new HashMap<>();

  public WebAuthNImpl(Vertx vertx, WebAuthNOptions options) {
    random = new PRNG(vertx);
    this.options = options;

    ServiceLoader<Attestation> serviceLoader = ServiceLoader.load(Attestation.class);

    for (Attestation att : serviceLoader) {
      attestations.put(att.fmt(), att);
    }

    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("SHA-256 is not available", nsae);
    }
  }

  private String randomBase64URLBuffer(int length) {
    final byte[] buff = new byte[length];
    random.nextBytes(buff);
    return b64enc.encodeToString(buff);
  }

  @Override
  public JsonObject generateServerCredentialsChallenge(String username, String displayName, String id, CredentialsChallengeType type) {
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
        throw new IllegalArgumentException("Unsupported Authenticator Attachment type: " + type);
    }

    return new JsonObject()
      .put("challenge", randomBase64URLBuffer(32))
      .put("rp", new JsonObject()
        .put("name", options.getRealm()))
      .put("user", new JsonObject()
        .put("id", id)
        .put("name", username)
        .put("displayName", displayName))
      .put("authenticatorSelection", authenticatorSelection)
      .put("attestation", "direct")
      .put("pubKeyCredParams", new JsonArray()
        .add(new JsonObject()
          .put("type", "public-key")
          .put("alg", -7)));
  }

  @Override
  public JsonObject generateServerGetAssertion(List<String> authenticatorIds) {
    JsonArray allowCredentials = new JsonArray();

    // STEP 19 Return allow credential ID
    for (String id : authenticatorIds) {
      allowCredentials
        .add(new JsonObject()
          .put("type", "public-key")
          .put("id", id)
          .put("transports", new JsonArray(options.getTransports())));
    }

    return new JsonObject()
      .put("challenge", randomBase64URLBuffer(options.getChallengeLength()))
      .put("allowCredentials", allowCredentials);
  }

  @Override
  public void authenticate(WebAuthNInfo authInfo, Handler<AsyncResult<User>> handler) {
    JsonObject webauthnResp = Objects.requireNonNull(authInfo.getWebauthn());

    final JsonObject response = webauthnResp.getJsonObject("response", EMPTY);

    JsonObject clientData = new JsonObject(Buffer.buffer(b64dec.decode(response.getString("clientDataJSON"))));

    // STEP 8 Verify challenge is match with cookie
    if (!clientData.getString("challenge").equals(authInfo.getChallenge())) {
      handler.handle(Future.failedFuture("Challenges don't match!"));
      return;
    }

    // STEP 9 Verify challenge is match with cookie
    if (!clientData.getString("origin").equals(options.getOrigin())) {
      handler.handle(Future.failedFuture("Origins don't match!"));
      return;
    }

    try {
      if (response.containsKey("attestationObject")) {
        // STEP 10 Verify attestation
        handler.handle(
          Future.succeededFuture(
            new WebAuthNUser(verifyAuthenticatorAttestationResponse(webauthnResp))));
      } else if (response.containsKey("authenticatorData")) {
        JsonArray authenticators = Objects.requireNonNull(authInfo.getAuthenticators());

        handler.handle(
          Future.succeededFuture(
            new WebAuthNUser(verifyAuthenticatorAssertionResponse(webauthnResp, authenticators))));
      } else {
        handler.handle(Future.failedFuture("Can not determine type of response!"));
      }
    } catch (IOException e) {
      handler.handle(Future.failedFuture(e));
    }
  }

  /**
   * Verify creadentials from client
   *
   * @param webAuthnResponse - Data from navigator.credentials.create
   */
  private JsonObject verifyAuthenticatorAttestationResponse(JsonObject webAuthnResponse) throws IOException {

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
  private JsonObject verifyAuthenticatorAssertionResponse(JsonObject webAuthnResponse, JsonArray authenticators) throws IOException {
    // STEP 24 Query public key base on user ID
    JsonObject authr = findAuthr(webAuthnResponse.getString("id"), authenticators);

    JsonObject response = webAuthnResponse.getJsonObject("response", EMPTY);
    // STEP 25 parse auth data
    byte[] authenticatorData = b64dec.decode(response.getString("authenticatorData"));
    AuthenticatorData authrDataStruct = new AuthenticatorData(authenticatorData);

    if ((authrDataStruct.getFlags() & AuthenticatorData.USER_PRESENT) == 0) {
      throw new RuntimeException("User was NOT present durring authentication!");
    }
    // STEP 26 hash clientDataJSON with sha256
    byte[] clientDataHash = hash(b64dec.decode(response.getString("clientDataJSON")));
    // STEP 27 create signature base by concat authenticatorData and clientDataHash
    Buffer signatureBase = Buffer.buffer()
      .appendBytes(authenticatorData)
      .appendBytes(clientDataHash);

    // STEP 28 format public key
    try (JsonParser parser = CBOR.cborParser(authr.getString("publicKey"))) {
      // the decoded credential primary as a JWK
      JWK publicKey = AuthenticatorData.parseJWK(new JsonObject(CBOR.<Map>parse(parser)));

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
   * Returns SHA-256 digest of the given data.
   *
   * @param data - data to hash
   * @return the hash
   */
  private byte[] hash(byte[] data) {
    synchronized (sha256) {
      sha256.update(data);
      return sha256.digest();
    }
  }

  /**
   * Takes an array of registered authenticators and find one specified by credID
   *
   * @param credID         - base64url encoded credential
   * @param authenticators - list of authenticators
   * @return found authenticator
   */
  private JsonObject findAuthr(String credID, JsonArray authenticators) {
    for (Object el : authenticators) {
      JsonObject authr = (JsonObject) el;
      if (credID.equals(authr.getValue("credID"))) {
        return authr;
      }
    }

    throw new RuntimeException("Unknown authenticator with credID: " + credID);
  }
}
