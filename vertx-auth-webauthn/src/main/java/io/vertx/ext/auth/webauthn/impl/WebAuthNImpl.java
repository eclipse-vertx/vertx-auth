package io.vertx.ext.auth.webauthn.impl;

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.webauthn.WebAuthN;
import io.vertx.ext.auth.webauthn.WebAuthNOptions;
import io.vertx.ext.auth.webauthn.WebAuthNStore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class WebAuthNImpl implements WebAuthN {

  /*
   * U2F Presence constant
   */
  private static final int U2F_USER_PRESENTED = 0x01;

  private final MessageDigest sha256;
  private final CertificateFactory x509;

  // codecs
  private final Base64.Encoder b64enc = Base64.getUrlEncoder().withoutPadding();
  private final Base64.Decoder b64dec = Base64.getUrlDecoder();
  private final ObjectMapper cbor = new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL);

  private final PRNG random;
  private final WebAuthNOptions options;

  private WebAuthNStore store;

  public WebAuthNImpl(Vertx vertx, WebAuthNOptions options) {
    random = new PRNG(vertx);
    this.options = options;

    try {
      sha256 = MessageDigest.getInstance("SHA-256");
      x509 = CertificateFactory.getInstance("X.509");
    } catch (NoSuchAlgorithmException | CertificateException nsae) {
      throw new RuntimeException(nsae);
    }
  }

  @Override
  public WebAuthN webAuthNStore(WebAuthNStore store) {
    this.store = store;
    return this;
  }

  private String randomBase64URLBuffer(int length) {
    final byte[] buff = new byte[length];
    random.nextBytes(buff);
    return b64enc.encodeToString(buff);
  }

  @Override
  public WebAuthN generateServerMakeCredRequest(String username, String displayName, Handler<AsyncResult<JsonObject>> handler) {
    store.find(username, find -> {
      if (find.succeeded()) {
        JsonObject user = find.result();
        if (user == null || !user.getBoolean("registered")) {
          // update the store
          final String id = randomBase64URLBuffer(32);

          user = new JsonObject()
            .put("name", displayName)
            .put("registered", false)
            .put("id", id)
            .put("authenticators", new JsonArray());

          store.update(username, user, update -> {
            if (update.succeeded()) {
              handler.handle(Future.succeededFuture(
                new JsonObject()
                  .put("challenge", randomBase64URLBuffer(32))
                  .put("rp", new JsonObject()
                    .put("name", options.getRealm()))
                  .put("user", new JsonObject()
                    .put("id", id)
                    .put("name", username)
                    .put("displayName", displayName))
                  .put("attestation", "direct")
                  .put("pubKeyCredParams", new JsonArray()
                    .add(new JsonObject()
                      .put("type", "public-key")
                      .put("alg", -7)))
              ));
            } else {
              handler.handle(Future.failedFuture(update.cause()));
            }
          });
        } else {
          handler.handle(Future.failedFuture("Username already exists!"));
        }
      } else {
        handler.handle(Future.failedFuture(find.cause()));
      }
    });
    return this;
  }

  @Override
  public WebAuthN generateServerGetAssertion(String username, Handler<AsyncResult<JsonObject>> handler) {
    store.find(username, find -> {
      if (find.succeeded()) {
        JsonObject user = find.result();
        if (user == null || !user.getBoolean("registered")) {
          handler.handle(Future.failedFuture("User does not exist!"));
        } else {
          final JsonArray allowCredentials = new JsonArray();

          for (Object el : user.getJsonArray("authenticators", new JsonArray())) {
            JsonObject authr = (JsonObject) el;
            allowCredentials.add(
              new JsonObject()
                .put("type", "public-key")
                .put("id", authr.getString("credID"))
                .put("transports", new JsonArray(options.getTransports())));
          }

          handler.handle(Future.succeededFuture(
            new JsonObject()
              .put("challenge", randomBase64URLBuffer(32))
              .put("allowCredentials", allowCredentials)
          ));
        }
      } else {
        handler.handle(Future.failedFuture(find.cause()));
      }
    });

    return this;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> handler) {
    final String username = authInfo.getString("username");
    final JsonObject webauthnResp = authInfo.getJsonObject("webauthn");

    store.find(username, find -> {
      if (find.succeeded()) {

        final JsonObject user = find.result();

        if (webauthnResp.getJsonObject("response").containsKey("attestationObject")) {
          try {
            /* This is create cred */
            JsonObject result = verifyAuthenticatorAttestationResponse(webauthnResp);

            if (result.getBoolean("verified")) {
              // update user
              user.getJsonArray("authenticators").add(result.getJsonObject("authrInfo"));
              user.put("registered", true);

              store.update(username, user, update -> {
                if (update.succeeded()) {
                  handler.handle(Future.succeededFuture(new WebAuthNUser(user)));
                } else {
                  handler.handle(Future.failedFuture(update.cause()));
                }
              });
            } else {
              handler.handle(Future.failedFuture("Can not authenticate signature!"));
            }
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
          }
        } else if (webauthnResp.getJsonObject("response").containsKey("authenticatorData")) {
          /* This is get assertion */
          try {
            JsonObject result = verifyAuthenticatorAssertionResponse(webauthnResp, user.getJsonArray("authenticators"));

            System.out.println(result.encodePrettily());

            if (result.getBoolean("verified")) {
              // update user
              store.update(username, user, update -> {
                if (update.succeeded()) {
                  handler.handle(Future.succeededFuture(new WebAuthNUser(user)));
                } else {
                  handler.handle(Future.failedFuture(update.cause()));
                }
              });
            } else {
              handler.handle(Future.failedFuture("Can not authenticate signature!"));
            }
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
          }
        } else {
          handler.handle(Future.failedFuture("Can not determine type of response!"));
        }
      } else {
        handler.handle(Future.failedFuture(find.cause()));
      }
    });
  }

  private JsonObject verifyAuthenticatorAttestationResponse(JsonObject webAuthnResponse) {
    byte[] attestationBuffer = b64dec.decode(webAuthnResponse.getJsonObject("response").getString("attestationObject"));

    try {
      Map ctapMakeCredResp = cbor.readValue(attestationBuffer, Map.class);
      Map attStmt = (Map) ctapMakeCredResp.get("attStmt");

      JsonObject response = new JsonObject()
        .put("verified", false);

      if ("fido-u2f".equals(ctapMakeCredResp.get("fmt"))) {
        AuthData authrDataStruct = parseMakeCredAuthData((byte[]) (ctapMakeCredResp.get("authData")));

        if ((authrDataStruct.flags & U2F_USER_PRESENTED) == 0) {
          throw new SecurityException("User was NOT presented during authentication!");
        }

        byte[] clientDataHash = hash(b64dec.decode(webAuthnResponse.getJsonObject("response").getString("clientDataJSON")));
        Buffer publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
        Buffer signatureBase = Buffer.buffer()
          // reservedByte
          .appendByte((byte) 0x00)
          .appendBytes(authrDataStruct.rpIdHash)
          .appendBytes(clientDataHash)
          .appendBytes(authrDataStruct.credID)
          .appendBuffer(publicKey);

        List x5c = (List) attStmt.get("x5c");

        X509Certificate x509Certificate = (X509Certificate) x509.generateCertificate(new ByteArrayInputStream((byte[]) x5c.get(0)));
        byte[] signature = (byte[]) attStmt.get("sig");

        final boolean verified = verifySignature(signature, signatureBase.getBytes(), x509Certificate);

        response.put("verified", verified);

        if (verified) {
          response.put("authrInfo", new JsonObject()
            .put("fmt", "fido-u2f")
            .put("publicKey", b64enc.encodeToString(publicKey.getBytes()))
            .put("counter", authrDataStruct.counter)
            .put("credID", b64enc.encodeToString(authrDataStruct.credID)));
        }
      } else if ("packed".equals(ctapMakeCredResp.get("fmt")) && attStmt.containsKey("x5c")) {
        AuthData authrDataStruct = parseMakeCredAuthData((byte[]) (ctapMakeCredResp.get("authData")));

        if ((authrDataStruct.flags & U2F_USER_PRESENTED) == 0) {
          throw new SecurityException("User was NOT presented during authentication!");
        }

        byte[] clientDataHash = hash(b64dec.decode(webAuthnResponse.getJsonObject("response").getString("clientDataJSON")));
        Buffer publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
        Buffer signatureBase = Buffer.buffer()
          .appendBytes((byte[]) ctapMakeCredResp.get("authData"))
          .appendBytes(clientDataHash);

        List x5c = (List) attStmt.get("x5c");
        X509Certificate x509Certificate = (X509Certificate) x509.generateCertificate(new ByteArrayInputStream((byte[]) x5c.get(0)));

        byte[] signature = (byte[]) attStmt.get("sig");

        // Getting requirements from https://www.w3.org/TR/webauthn/#packed-attestation
        byte[] aaguid_ext = x509Certificate.getExtensionValue("1.3.6.1.4.1.45724.1.1.4");

        final boolean verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
          // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
          verifySignature(signature, signatureBase.getBytes(), x509Certificate) &&
            // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
            x509Certificate.getVersion() == 3; // &&
        // TODO:!
//            // ISO 3166 valid country
//            typeof iso_3166_1.whereAlpha2(pem.subject.countryName) != = 'undefined' &&
//          // Legal name of the Authenticator vendor (UTF8String)
//          pem.subject.organizationName &&
//          // Literal string “Authenticator Attestation” (UTF8String)
//          pem.subject.organizationalUnitName == = 'Authenticator Attestation' &&
//          // A UTF8String of the vendor’s choosing
//          pem.subject.commonName &&
//          // The Basic Constraints extension MUST have the CA component set to false
//          !pem.extensions.isCA &&
//          // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
//          // verify that the value of this extension matches the aaguid in authenticatorData.
//          // The extension MUST NOT be marked as critical.
//          (aaguid_ext != null ?
//            (authrDataStruct.hasOwnProperty('aaguid') ?
//              !aaguid_ext.critical && aaguid_ext.value.slice(2).equals(authrDataStruct.aaguid) : false)
//            : true);

        response.put("verified", verified);

        if (verified) {
          response.put("authrInfo", new JsonObject()
            .put("fmt", "fido-u2f")
            .put("publicKey", b64enc.encodeToString(publicKey.getBytes()))
            .put("counter", authrDataStruct.counter)
            .put("credID", b64enc.encodeToString(authrDataStruct.credID)));
        }

      } else {
        throw new RuntimeException("Unsupported attestation format! " + ctapMakeCredResp.get("fmt"));
      }

      return response;
    } catch (IOException | CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  private JsonObject verifyAuthenticatorAssertionResponse(JsonObject webAuthnResponse, JsonArray authenticators) {

    try {

      JsonObject authr = findAuthr(webAuthnResponse.getString("id"), authenticators);
      byte[] authenticatorData = b64dec.decode(webAuthnResponse.getJsonObject("response").getString("authenticatorData"));

      JsonObject response = new JsonObject()
        .put("verified", false);

      if ("fido-u2f".equals(authr.getString("fmt"))) {
        AuthData authrDataStruct = parseGetAssertAuthData(authenticatorData);

        if ((authrDataStruct.flags & U2F_USER_PRESENTED) == 0) {
          throw new SecurityException("User was NOT presented during authentication!");
        }

        byte[] clientDataHash = hash(b64dec.decode(webAuthnResponse.getJsonObject("response").getString("clientDataJSON")));
        Buffer signatureBase = Buffer.buffer()
          .appendBytes(authrDataStruct.rpIdHash)
          .appendByte(authrDataStruct.flags)
          .appendUnsignedInt(authrDataStruct.counter)
          .appendBytes(clientDataHash);

        byte[] signature = b64dec.decode(webAuthnResponse.getJsonObject("response").getString("signature"));

        System.out.println(authr.getString("publicKey"));

        final X509EncodedKeySpec keyspec = new X509EncodedKeySpec(raw2ASN1(b64dec.decode(authr.getString("publicKey"))));
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(keyspec);

        final boolean verified = verifySignature(signature, signatureBase.getBytes(), publicKey);

        response.put("verified", verified);

        if (verified) {

          System.out.println("response <== " + response.encodePrettily());
          System.out.println("authr <== " + authr.encodePrettily());

          // TODO: there's no state on counter so this is not correct!
          if (response.containsKey("counter") && response.getInteger("counter") <= authr.getInteger("counter")) {
            throw new SecurityException("Authr counter did not increase!");
          }

          authr.put("counter", authrDataStruct.counter);
        }
      }

      return response;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }

  }

  /**
   * Parses authenticatorData buffer.
   *
   * @param bytes - authenticatorData buffer
   * @return parsed authenticatorData struct
   */
  private AuthData parseMakeCredAuthData(byte[] bytes) {
    Buffer buffer = Buffer.buffer(bytes);
    int pos = 0;

    byte[] rpIdHash = buffer.getBytes(pos, pos + 32);
    pos += 32;

    byte flags = buffer.getByte(pos);
    pos += 1;

    long counter = buffer.getUnsignedInt(pos);
    pos += 4;

    byte[] aaguid = buffer.getBytes(pos, pos + 16);
    pos += 16;

    int credIDLen = buffer.getUnsignedShort(pos);
    pos += 2;

    byte[] credID = buffer.getBytes(pos, pos + credIDLen);
    pos += credIDLen;

    byte[] COSEPublicKey = buffer.getBytes(pos, bytes.length);

    final AuthData authData = new AuthData();

    authData.rpIdHash = rpIdHash;
    authData.flags = flags;
    authData.counter = counter;
    authData.aaguid = aaguid;
    authData.credID = credID;
    authData.COSEPublicKey = COSEPublicKey;

    return authData;
  }

  /**
   * Parses AuthenticatorData from GetAssertion response
   *
   * @param bytes - Auth data buffer
   * @return parsed authenticatorData struct
   */
  private AuthData parseGetAssertAuthData(byte[] bytes) {
    Buffer buffer = Buffer.buffer(bytes);
    int pos = 0;

    byte[] rpIdHash = buffer.getBytes(pos, pos + 32);
    pos += 32;

    byte flags = buffer.getByte(pos);
    pos += 1;

    long counter = buffer.getUnsignedInt(pos);
    pos += 4;

    final AuthData authData = new AuthData();
    authData.rpIdHash = rpIdHash;
    authData.flags = flags;
    authData.counter = counter;

    return authData;
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

  private boolean verifySignature(byte[] signature, byte[] data, X509Certificate certificate) {

    try {
      Signature sig = Signature.getInstance("SHA256withECDSA");

      sig.initVerify(certificate);
      sig.update(data);
      return sig.verify(signature);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  private boolean verifySignature(byte[] signature, byte[] data, PublicKey publicKey) {

    try {
      Signature sig = Signature.getInstance("SHA256withECDSA");

      sig.initVerify(publicKey);
      sig.update(data);
      return sig.verify(signature);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  /**
   * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
   *
   * @param COSEPublicKey COSE encoded public key
   * @return RAW PKCS encoded public key
   */
  private Buffer COSEECDHAtoPKCS(byte[] COSEPublicKey) throws IOException {
    /*
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    Map coseStruct = cbor.readValue(COSEPublicKey, Map.class);

    return Buffer.buffer()
      // tag
      .appendByte((byte) 0x04)
      .appendBytes((byte[]) coseStruct.get("-2"))
      .appendBytes((byte[]) coseStruct.get("-3"));
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

    throw new RuntimeException("Unknown authenticator with credID " + credID + "!");
  }

  /**
   * Convert binary certificate or public key to an ASN.1 encoded buffer.
   *
   * @param pkBuffer - Cert or PubKey buffer
   * @return ASN.1
   */
  private byte[] raw2ASN1(byte[] pkBuffer) {

    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */

      return Buffer.buffer(new byte[] {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00})
        .appendBytes(pkBuffer).getBytes();
    } else {
      return pkBuffer;
    }
  }
}

class AuthData {
  byte[] rpIdHash;
  byte flags;
  long counter;
  byte[] aaguid;
  byte[] credID;
  byte[] COSEPublicKey;
}
