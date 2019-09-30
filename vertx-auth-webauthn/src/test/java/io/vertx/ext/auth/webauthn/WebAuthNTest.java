package io.vertx.ext.auth.webauthn;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class WebAuthNTest {

  private Vertx vertx = Vertx.vertx();

  @Test
  public void testVerifyAuthenticatorAttestationResponse() {
    WebAuthN webAuthN = WebAuthN.create(vertx, new WebAuthNOptions().setRealm("FIDO Examples Corporation"));

    final JsonObject webauthn = new JsonObject("{\"getClientExtensionResults\":{},\"rawId\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"response\":{\"attestationObject\":\"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAOOPecQ34VN0QW-cmj-Sft9aCahqgTlFQzbQH1LpEgrTAiBWW6KoqlKbLMtGd1Y_VcQML8eugYZcrmSSCS0of2T-M2N4NWOBWQIyMIICLjCCARigAwIBAgIECmML_zALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCkxJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDE3NDI2MzI5NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKQjZF26iyPtbNnl5IuTKs_fRWTHVzHxz1IHRRBrSbqWD60PCqUJPe4zkIRFqBa4NnzdhVcS80nlZuY3ANQm0J-jJjAkMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMAsGCSqGSIb3DQEBCwOCAQEAZTmwMqHPxEjSB64Umwq2tGDKplAcEzrwmg6kgS8KPkJKXKSu9T1H6XBM9-LAE9cN48oUirFFmDIlTbZRXU2Vm2qO9OdrSVFY-qdbF9oti8CKAmPHuJZSW6ii7qNE59dHKUaP4lDYpnhRDqttWSUalh2LPDJQUpO9bsJPkgNZAhBUQMYZXL_MQZLRYkX-ld7llTNOX5u7n_4Y5EMr-lqOyVVC9lQ6JP6xoa9q6Zp9-Y9ZmLCecrrcuH6-pLDgAzPcc8qxhC2OR1B0ZSpI9RBgcT0KqnVE0tq1KEDeokPqF3MgmDRkJ--_a2pV0wAYfPC3tC57BtBdH_UXEB8xZVFhtGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQL6enL6EoL01kshaZ5naZtXcIrkRL7JviqsNCbdGND0H4x7BIShPNiqJqVF6hLeckCEJfWSo-i9fu9NCxmlVDKGlAQIDJiABIVgg0TT3Vc7gnmO4ptAzJ671fahlgW8CrqgiCn_fPWFeEbciWCD9wLIGCTxTxmbe6ahfYQuboizWT7Y8u3BaYKSa6XTtxA\",\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiJQZXlodVVYaVQzeG55V1pqZWNaU1NxaFVTdUttYmZPV0dGREN0OGZDUXYwIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9\"},\"id\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"type\":\"public-key\"}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
      , fn -> {
        if (fn.succeeded()) {
          System.out.println(fn.result());
        } else {
          fn.cause().printStackTrace();
        }
      });
  }

  @Test
  public void testLogin() {
    WebAuthN webAuthN = WebAuthN.create(vertx, new WebAuthNOptions().setRealm("FIDO Examples Corporation"));

    final JsonObject webauthn = new JsonObject("{\"getClientExtensionResults\":{},\"rawId\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"response\":{\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAADg\",\"signature\":\"MEUCIQDZDN5FQmDPh1bqayvaXVs8HqwlPHuiAPhIAGx3GmDp_gIgMVLdNPYy1jwOYP7QC7FuO8Pfux0UlFLS417I1SCbCYM\",\"userHandle\":null,\"clientDataJSON\":\"eyJjaGFsbGVuZ2UiOiJxSzhfNFoxYUh3S0FjU2UtOEEwbTB5RGZsRWZTaTBqRC1NVW85ZWZ1cGNzIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9\"},\"id\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\",\"type\":\"public-key\"}");

    webAuthN.authenticate(
      new JsonObject()
        .put("webauthn", webauthn)
        .put("authenticators", new JsonArray()
          .add(new JsonObject("{\"fmt\":\"fido-u2f\",\"publicKey\":\"pQECAyYgASFYINE091XO4J5juKbQMyeu9X2oZYFvAq6oIgp_3z1hXhG3Ilgg_cCyBgk8U8Zm3umoX2ELm6Is1k-2PLtwWmCkmul07cQ\",\"counter\":0,\"credID\":\"vp6cvoSgvTWSyFpnmdpm1dwiuREvsm-Kqw0Jt0Y0PQfjHsEhKE82KompUXqEt5yQIQl9ZKj6L1-700LGaVUMoQ\"}")))
      , fn -> {
        if (fn.succeeded()) {
          System.out.println(fn.result());
        } else {
          fn.cause().printStackTrace();
        }
      });
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

  @Test
  public void testPKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    Base64.Decoder b64dec = Base64.getUrlDecoder();

    String k = "BOEptHmHWjimuIdBo8lKI8WOXmT9uXa5gQbXyQy8jXPVl1AyBfUO8gUxYQMwATVRBEMHXa6xZlqtfs7LEuEJOU8";

    byte[] key = b64dec.decode(k);
    final KeySpec keyspec = new X509EncodedKeySpec(raw2ASN1(key));

    PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(keyspec);

  }
}
