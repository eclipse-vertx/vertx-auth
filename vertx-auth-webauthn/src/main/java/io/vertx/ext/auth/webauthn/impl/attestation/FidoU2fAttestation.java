package io.vertx.ext.auth.webauthn.impl.attestation;

import com.fasterxml.jackson.core.JsonParser;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;
import io.vertx.ext.auth.webauthn.impl.CBOR;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import static io.vertx.ext.auth.webauthn.impl.AuthenticatorData.USER_PRESENT;

public class FidoU2fAttestation implements Attestation {

  private static final Logger LOG = LoggerFactory.getLogger(FidoU2fAttestation.class);

  // codecs
  private static final Base64.Decoder b64dec = Base64.getUrlDecoder();

  private final MessageDigest sha256;
  private final CertificateFactory x509;
  private final Signature sig;

  public FidoU2fAttestation() {
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
      x509 = CertificateFactory.getInstance("X.509");
      sig = Signature.getInstance("SHA256withECDSA");
    } catch (NoSuchAlgorithmException | CertificateException e) {
      throw new AttestationException(e);
    }
  }

  @Override
  public String fmt() {
    return "fido-u2f";
  }

  @Override
  public boolean verify(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject ctapMakeCredResp, AuthenticatorData authr) {
    try {
      if (!authr.is(USER_PRESENT)) {
        throw new AttestationException("User was NOT present during authentication!");
      }

      byte[] clientDataHash = hash(clientDataJSON);

      byte[] publicKey = COSEECDHAtoPKCS(authr.getCredentialPublicKey());
      Buffer signatureBase = Buffer.buffer()
        .appendByte((byte) 0x00) // reserved byte
        .appendBytes(authr.getRpIdHash())
        .appendBytes(clientDataHash)
        .appendBytes(authr.getCredentialId())
        .appendBytes(publicKey);

      JsonObject attStmt = ctapMakeCredResp.getJsonObject("attStmt");
      JsonArray x5c = attStmt.getJsonArray("x5c");

      final X509Certificate x509Certificate = (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(b64dec.decode(x5c.getString(0))));
      byte[] signature = b64dec.decode(attStmt.getString("sig"));

      return verifySignature(signature, signatureBase.getBytes(), x509Certificate);
    } catch (CertificateException | IOException e) {
      throw new AttestationException(e);
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

  private boolean verifySignature(byte[] signature, byte[] data, X509Certificate certificate) {
    try {
      synchronized (sig) {
        sig.initVerify(certificate);
        sig.update(data);
        return sig.verify(signature);
      }
    } catch (Exception e) {
      LOG.warn("Failed to verify attestation", e);
      return false;
    }
  }

  /**
   * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
   *
   * @param cosePublicKey - COSE encoded public key
   * @return - RAW PKCS encoded public key
   */
  private static byte[] COSEECDHAtoPKCS(byte[] cosePublicKey) throws IOException {
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
      try (JsonParser parser = CBOR.cborParser(cosePublicKey)) {
        Map key = CBOR.parse(parser);

        return Buffer.buffer()
          .appendByte((byte) 0x04)
          .appendBytes(b64dec.decode((String) key.get("-2")))
          .appendBytes(b64dec.decode((String) key.get("-3")))
          .getBytes();
      }
  }
}
