/*
 * Copyright 2015 Red Hat, Inc.
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
package io.vertx.ext.auth.oauth2.impl.crypto;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * This is a special crypto utility class for jwt tokens
 */
public final class TokenVerifier {

  private static final Logger log = LoggerFactory.getLogger(TokenVerifier.class);
  private static final JsonObject EMPTY_JSON = new JsonObject();
  private static final Charset UTF8 = StandardCharsets.UTF_8;

  private final Signature sig;
  private final PublicKey publicKey;

  public TokenVerifier(final String key) {
    if (key == null) {
      sig = null;
      publicKey = null;
    } else {
      try {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        publicKey = kf.generatePublic(spec);
        sig = Signature.getInstance("SHA256withRSA");

      } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        throw new RuntimeException(e);
      }
    }
  }

  public synchronized JsonObject verify(String accessToken) {
    if (accessToken == null || sig == null || publicKey == null) {
      return EMPTY_JSON;
    }

    try {
      String[] segments = accessToken.split("\\.");
      if (segments.length == 3) {
        // All segment should be base64
        String headerSeg = segments[0];
        String payloadSeg = segments[1];

        final JsonObject header = new JsonObject(new String(base64urlDecode(headerSeg), UTF8));

        if ("RS256".equals(header.getString("alg"))) {
          // this is the right algorithm
          final String signature = segments[2];
          final String signed = headerSeg + "." + payloadSeg;

          sig.initVerify(publicKey);
          sig.update(signed.getBytes());

          if(sig.verify(base64urlDecode(signature))) {
            return new JsonObject(new String(base64urlDecode(payloadSeg), UTF8));
          } else {
            log.error("bad signature");
          }
        } else {
          log.error("token contains unknown alg: " + header.getString("alg"));
        }
      }

    } catch (SignatureException | InvalidKeyException | RuntimeException e) {
      log.error(e);
    }

    return EMPTY_JSON;
  }

  private static byte[] base64urlDecode(String str) {
    return Base64.getUrlDecoder().decode(str.getBytes(UTF8));
  }
}
