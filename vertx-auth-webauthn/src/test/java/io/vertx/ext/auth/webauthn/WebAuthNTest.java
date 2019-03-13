package io.vertx.ext.auth.webauthn;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
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
  public void testRegister() {
    WebAuthN webAuthN = WebAuthN.create(vertx, new WebAuthNOptions().setRealm("FIDO Examples Corporation"));
    webAuthN.webAuthNStore(new WebAuthNStore() {
      final Map<String, JsonObject> database = new HashMap<>();

      @Override
      public WebAuthNStore find(String id, Handler<AsyncResult<JsonObject>> handler) {
        handler.handle(Future.succeededFuture(database.get(id)));
        return this;
      }

      @Override
      public WebAuthNStore update(String id, JsonObject data, Handler<AsyncResult<JsonObject>> handler) {
        handler.handle(Future.succeededFuture(database.put(id, data)));
        return this;
      }
    });

    webAuthN.generateServerMakeCredRequest("pmlopes", "Paulo", fn -> {
      if (fn.succeeded()) {
        System.out.println(fn.result().encodePrettily());
      } else {
        fn.cause().printStackTrace();
      }
    });

//    webAuthN.authenticate(
//      new JsonObject()
//        .put("username", "pmlopes")
//        .put("webauthn", new JsonObject("{\n" +
//          "  \"getClientExtensionResults\": {},\n" +
//          "  \"rawId\": \"iK_S5PkViBG7A2MbJ6s22Rf213u2B9TrvdM1yuf9XXC8YfD8-dXixnZrvY7stcwzui1QiVjweyCMT-nCxnltWw\",\n" +
//          "  \"response\": {\n" +
//          "    \"attestationObject\": \"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgN_kqJPm8_TnNb13HKtRYzrJ4rcmIc2FkolgNTtNIkHUCIQDRTS3lvDexrTdbVFUPe0O6GE3QRcygX1OrUwLdKEk7gWN4NWOBWQIyMIICLjCCARigAwIBAgIECmML_zALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCkxJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDE3NDI2MzI5NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKQjZF26iyPtbNnl5IuTKs_fRWTHVzHxz1IHRRBrSbqWD60PCqUJPe4zkIRFqBa4NnzdhVcS80nlZuY3ANQm0J-jJjAkMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMAsGCSqGSIb3DQEBCwOCAQEAZTmwMqHPxEjSB64Umwq2tGDKplAcEzrwmg6kgS8KPkJKXKSu9T1H6XBM9-LAE9cN48oUirFFmDIlTbZRXU2Vm2qO9OdrSVFY-qdbF9oti8CKAmPHuJZSW6ii7qNE59dHKUaP4lDYpnhRDqttWSUalh2LPDJQUpO9bsJPkgNZAhBUQMYZXL_MQZLRYkX-ld7llTNOX5u7n_4Y5EMr-lqOyVVC9lQ6JP6xoa9q6Zp9-Y9ZmLCecrrcuH6-pLDgAzPcc8qxhC2OR1B0ZSpI9RBgcT0KqnVE0tq1KEDeokPqF3MgmDRkJ--_a2pV0wAYfPC3tC57BtBdH_UXEB8xZVFhtGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIiv0uT5FYgRuwNjGyerNtkX9td7tgfU673TNcrn_V1wvGHw_PnV4sZ2a72O7LXMM7otUIlY8HsgjE_pwsZ5bVulAQIDJiABIVggJ3pWDklZKA8IaOZKY7pD8vU9lJk8PC2dsR-C23G2Ph4iWCBzd46PsdRc8o1A_4l6uMiJahAn6ig_JRcjfDY3_YH3Ow\",\n" +
//          "    \"clientDataJSON\": \"eyJjaGFsbGVuZ2UiOiJMY0llZzRHZVNGUzIwNExPWE5wNFpleDMtR29oUW0yQi1KOXRMaGVfS1NFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9\"\n" +
//          "  },\n" +
//          "  \"id\": \"iK_S5PkViBG7A2MbJ6s22Rf213u2B9TrvdM1yuf9XXC8YfD8-dXixnZrvY7stcwzui1QiVjweyCMT-nCxnltWw\",\n" +
//          "  \"type\": \"public-key\"\n" +
//          "}")), fn -> {
//        if (fn.succeeded()) {
//          System.out.println(fn.result());
//        } else {
//          fn.cause().printStackTrace();
//        }
//      });
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
    final KeySpec keyspec = new X509EncodedKeySpec(raw2ASN1(key).getBytes());

    PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(keyspec);

  }
}
