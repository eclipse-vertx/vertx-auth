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
package io.vertx.ext.auth.jwt.impl;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import javax.crypto.Mac;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * JWT and JWS implementation draft-ietf-oauth-json-web-token-32.
 *
 * @author Paulo Lopes
 */
public final class JWT {

  private static final Charset UTF8 = StandardCharsets.UTF_8;
  private static final Logger log = LoggerFactory.getLogger(JWT.class);
  private static final JsonObject EMPTY = new JsonObject();

  private final Map<String, Crypto> cryptoMap;
  private final boolean unsecure;

  public JWT(final KeyStore keyStore, final char[] keyStorePassword) {

    Map<String, Crypto> tmp = new HashMap<>();

    unsecure = keyStore == null;

    if (!unsecure) {
      // load MACs
      for (String alg : Arrays.<String>asList("HS256", "HS384", "HS512")) {
        try {
          Mac mac = getMac(keyStore, keyStorePassword, alg);
          if (mac != null) {
            tmp.put(alg, new CryptoMac(mac));
          } else {
            log.info(alg + " not available");
          }
        } catch (RuntimeException e) {
          log.warn(alg + " not supported", e);
        }
      }

      // load SIGNATUREs
      final Map<String, String> alias = new HashMap<String, String>() {{
        put("RS256", "SHA256withRSA");
        put("RS384", "SHA384withRSA");
        put("RS512", "SHA512withRSA");
        put("ES256", "SHA256withECDSA");
        put("ES384", "SHA384withECDSA");
        put("ES512", "SHA512withECDSA");
      }};

      for (String alg : Arrays.<String>asList("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")) {
        try {
          X509Certificate certificate = getCertificate(keyStore, alg);
          PrivateKey privateKey = getPrivateKey(keyStore, keyStorePassword, alg);
          if (certificate != null && privateKey != null) {
            tmp.put(alg, new CryptoSignature(alias.get(alg), certificate, privateKey));
          } else {
            log.info(alg + " not available");
          }
        } catch (RuntimeException e) {
          e.printStackTrace();
          log.warn(alg + " not supported");
        }
      }
    }

    // Spec requires "none" to always be available
    tmp.put("none", new CryptoNone());

    cryptoMap = Collections.unmodifiableMap(tmp);
  }

  public JWT(String publicKey) {
    Map<String, Crypto> tmp = new HashMap<>();

    unsecure = publicKey == null;

    if (!unsecure) {
      // load SIGNATURE (Read Only)
      try {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        tmp.put("RS256", new CryptoPublicKey("SHA256withRSA",  kf.generatePublic(spec)));
      } catch (InvalidKeySpecException | NoSuchAlgorithmException | RuntimeException e) {
        e.printStackTrace();
        log.warn("RS256 not supported");
      }
    }

    // Spec requires "none" to always be available
    tmp.put("none", new CryptoNone());

    cryptoMap = Collections.unmodifiableMap(tmp);
  }

  /**
   * Creates a new Message Authentication Code
   *
   * @param keyStore a valid JKS
   * @param alias    algorithm to use e.g.: HmacSHA256
   * @return Mac implementation
   */
  private Mac getMac(final KeyStore keyStore, final char[] keyStorePassword, final String alias) {
    try {
      final Key secretKey = keyStore.getKey(alias, keyStorePassword);
      
      // key store does not have the requested algorithm
      if (secretKey == null) {
        return null;
      }

      Mac mac = Mac.getInstance(secretKey.getAlgorithm());
      mac.init(secretKey);

      return mac;
    } catch (NoSuchAlgorithmException | InvalidKeyException | UnrecoverableKeyException | KeyStoreException e) {
      throw new RuntimeException(e);
    }
  }

  private X509Certificate getCertificate(final KeyStore keyStore, final String alias) {
    try {
      return (X509Certificate) keyStore.getCertificate(alias);

    } catch (KeyStoreException e) {
      throw new RuntimeException(e);
    }
  }

  private PrivateKey getPrivateKey(final KeyStore keyStore, final char[] keyStorePassword, final String alias) {
    try {
      return (PrivateKey) keyStore.getKey(alias, keyStorePassword);

    } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
      throw new RuntimeException(e);
    }
  }

  public JsonObject decode(final String token) {
    String[] segments = token.split("\\.");
    if (segments.length != (unsecure ? 2 : 3)) {
      throw new RuntimeException("Not enough or too many segments");
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = unsecure ? null : segments[2];

    if ("".equals(signatureSeg)) {
      throw new RuntimeException("Signature is required");
    }

    // base64 decode and parse JSON
    JsonObject header = new JsonObject(new String(base64urlDecode(headerSeg), UTF8));
    JsonObject payload = new JsonObject(new String(base64urlDecode(payloadSeg), UTF8));

    String alg = header.getString("alg");

    Crypto crypto = cryptoMap.get(alg);

    if (crypto == null) {
      throw new RuntimeException("Algorithm not supported");
    }

    // if we only allow secure alg, then none is not a valid option
    if (!unsecure && "none".equals(alg)) {
      throw new RuntimeException("Algorithm \"none\" not allowed");
    }

    // verify signature. `sign` will return base64 string.
    if (!unsecure) {
      String signingInput = headerSeg + "." + payloadSeg;

      if (!crypto.verify(base64urlDecode(signatureSeg), signingInput.getBytes(UTF8))) {
        throw new RuntimeException("Signature verification failed");
      }
    }

    return payload;
  }

  public String sign(JsonObject payload, JsonObject options) {
    final String algorithm = options.getString("algorithm", "HS256");

    Crypto crypto = cryptoMap.get(algorithm);

    if (crypto == null) {
      throw new RuntimeException("Algorithm not supported");
    }

    // header, typ is fixed value.
    JsonObject header = new JsonObject()
            .mergeIn(options.getJsonObject("header", EMPTY))
            .put("typ", "JWT")
            .put("alg", algorithm);

    // NumericDate is a number is seconds since 1st Jan 1970 in UTC
    long timestamp = System.currentTimeMillis() / 1000;

    if (!options.getBoolean("noTimestamp", false)) {
      payload.put("iat", payload.getValue("iat", timestamp));
    }

    Long expiresInSeconds;

    if (options.containsKey("expiresInMinutes")) {
      expiresInSeconds = options.getLong("expiresInMinutes") * 60;
    } else {
      expiresInSeconds = options.getLong("expiresInSeconds");
    }

    if (expiresInSeconds != null) {
      payload.put("exp", timestamp + expiresInSeconds);
    }

    if (options.containsKey("audience")) {
      payload.put("aud", options.getValue("audience"));
    }

    if (options.containsKey("issuer")) {
      payload.put("iss", options.getValue("issuer"));
    }

    if (options.containsKey("subject")) {
      payload.put("sub", options.getValue("subject"));
    }

    // create segments, all segment should be base64 string
    String headerSegment = base64urlEncode(header.encode());
    String payloadSegment = base64urlEncode(payload.encode());
    String signingInput = headerSegment + "." + payloadSegment;
    String signSegment = base64urlEncode(crypto.sign(signingInput.getBytes(UTF8)));

    return headerSegment + "." + payloadSegment + "." + signSegment;
  }

  private static byte[] base64urlDecode(String str) {
    return Base64.getUrlDecoder().decode(str.getBytes(UTF8));
  }

  private static String base64urlEncode(String str) {
    return base64urlEncode(str.getBytes(UTF8));
  }

  private static String base64urlEncode(byte[] bytes) {
    return Base64.getUrlEncoder().encodeToString(bytes);
  }
}
