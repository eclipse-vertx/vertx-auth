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
package io.vertx.ext.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * JWT and JWS implementation draft-ietf-oauth-json-web-token-32.
 *
 * @author Paulo Lopes
 */
public final class JWT {

  private static final List<String> PUBSEC_ALGS = Arrays.asList("RS256", "RS384", "RS512", "ES256", "ES384", "ES512");
  private static final List<String> MAC_ALGS = Arrays.asList("HS256", "HS384", "HS512");
  // simple random as its value is just to create entropy
  private static final Random RND = new Random();

  private static final Map<String, String> ALGORITHM_ALIAS = new HashMap<String, String>() {{
    put("HS256", "HMacSHA256");
    put("HS384", "HMacSHA384");
    put("HS512", "HMacSHA512");
    put("RS256", "SHA256withRSA");
    put("RS384", "SHA384withRSA");
    put("RS512", "SHA512withRSA");
    put("ES256", "SHA256withECDSA");
    put("ES384", "SHA384withECDSA");
    put("ES512", "SHA512withECDSA");
  }};

  private static final Charset UTF8 = StandardCharsets.UTF_8;
  private static final Logger log = LoggerFactory.getLogger(JWT.class);
  private static final JsonObject EMPTY = new JsonObject();

  // as described in the terminology section: https://tools.ietf.org/html/rfc7515#section-2
  private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder decoder = Base64.getUrlDecoder();

  private final Map<String, List<Crypto>> cryptoMap = new HashMap<>();

  public JWT() {
    // Spec requires "none" to always be available
    cryptoMap.put("none", Collections.singletonList(new CryptoNone()));
  }

  public JWT(final KeyStore keyStore, final char[] keyStorePassword) {
    this();

    // load MACs
    for (String alg : Arrays.asList("HS256", "HS384", "HS512")) {
      try {
        Mac mac = getMac(keyStore, keyStorePassword, alg);
        if (mac != null) {
          List<Crypto> l = cryptoMap.computeIfAbsent(alg, k -> new ArrayList<>());
          l.add(new CryptoMac(mac));
        } else {
          log.info(alg + " not available");
        }
      } catch (RuntimeException e) {
        log.warn(alg + " not supported", e);
      }
    }

    for (String alg : Arrays.asList("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")) {
      try {
        X509Certificate certificate = getCertificate(keyStore, alg);
        PrivateKey privateKey = getPrivateKey(keyStore, keyStorePassword, alg);
        if (certificate != null && privateKey != null) {
          List<Crypto> l = cryptoMap.computeIfAbsent(alg, k -> new ArrayList<>());
          l.add(new CryptoSignature(ALGORITHM_ALIAS.get(alg), certificate, privateKey));
        } else {
          log.info(alg + " not available");
        }
      } catch (RuntimeException e) {
        e.printStackTrace();
        log.warn(alg + " not supported");
      }
    }
  }

  @Deprecated
  public JWT(String key, boolean keyPrivate) {
    // make sure the none is present
    this();

    if (keyPrivate) {
      addSecretKey("RS256", key);
    } else {
      addPublicKey("RS256", key);
    }
  }

  private static KeyFactory getKeyFactoryFor(String algorithm) throws NoSuchAlgorithmException {
    switch (algorithm.charAt(0)) {
      case 'R':
        return KeyFactory.getInstance("RSA");
      case 'E':
        return KeyFactory.getInstance("EC");
      default:
        throw new RuntimeException("Unknown algorithm factory for: " + algorithm);
    }
  }

  /**
   * Adds a JSON Web Key (rfc7517) to the crypto map.
   *
   * @param jwk a JSON Web Key
   * @return self
   */
  public JWT addJWK(JWK jwk) {
    List<Crypto> current = cryptoMap.computeIfAbsent(jwk.getAlgorithm(), k -> new ArrayList<>());

    boolean replaced = false;

    for (int i = 0; i < current.size(); i++) {
      if (current.get(i).getId().equals(jwk.getId())) {
        // replace
        current.set(i, jwk);
        replaced = true;
      }
    }

    if (!replaced) {
      // non existent, add it!
      current.add(jwk);
    }

    return this;
  }

  /**
   * Adds a public key for a given JWS algorithm to the crypto map. This is an alternative to using keystores since
   * it is common to see these keys when dealing with 3rd party services such as Google or Keycloak.
   *
   * @param algorithm the JWS algorithm, e.g.: RS256
   * @param key       the base64 DER format of the key (also known as PEM format, without the header and footer).
   * @return self
   */
  public JWT addPublicKey(String algorithm, String key) {
    return addKeyPair(algorithm, key, null);
  }

  /**
   * Adds a key pair for a given JWS algorithm to the crypto map. This is an alternative to using keystores since
   * it is common to see these keys when dealing with 3rd party services such as Google or Keycloak.
   *
   * @param algorithm  the JWS algorithm, e.g.: RS256
   * @param publicKey  the base64 DER format of the key (also known as PEM format, without the header and footer).
   * @param privateKey the base64 DER format of the key (also known as PEM format, without the header and footer).
   * @return self
   */
  public JWT addKeyPair(String algorithm, String publicKey, String privateKey) {
    if (!PUBSEC_ALGS.contains(algorithm)) {
      throw new RuntimeException("Unknown algorithm: " + algorithm);
    }

    if (publicKey == null || privateKey == null) {
      cryptoMap.remove(algorithm);
      if (publicKey == null && privateKey == null) {
        return this;
      }
    }

    try {
      final PublicKey pub;
      final PrivateKey sec;

      if (publicKey != null) {
        // factory for public key
        final KeyFactory pubkf = getKeyFactoryFor(algorithm);
        final X509EncodedKeySpec pubspec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(publicKey));
        pub = pubkf.generatePublic(pubspec);
      } else {
        pub = null;
      }

      if (privateKey != null) {
        // factory for the private key
        final KeyFactory seckf = getKeyFactoryFor(algorithm);
        final KeySpec secspec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(privateKey));
        sec = seckf.generatePrivate(secspec);
      } else {
        sec = null;
      }

      List<Crypto> l = cryptoMap.computeIfAbsent(algorithm, k -> new ArrayList<>());
      l.add(new CryptoKeyPair(ALGORITHM_ALIAS.get(algorithm), pub, sec));

    } catch (InvalidKeySpecException | NoSuchAlgorithmException | RuntimeException e) {
      throw new RuntimeException(algorithm + " not supported", e);
    }

    return this;
  }

  /**
   * Adds a private key for a given JWS algorithm to the crypto map. This is an alternative to using keystores since
   * it is common to see these keys when dealing with 3rd party services such as Google.
   *
   * @param algorithm the JWS algorithm, e.g.: RS256
   * @param key       the base64 DER format of the key (also known as PEM format, without the header and footer).
   * @return self
   */
  public JWT addSecretKey(String algorithm, String key) {
    return addKeyPair(algorithm, null, key);
  }

  /**
   * Adds a certificate for a given JWS algorithm to the crypto map. This is an alternative to using keystores since
   * it is common to see these keys when dealing with 3rd party services such as Google.
   *
   * @param algorithm the JWS algorithm, e.g.: RS256
   * @param cert       the base64 DER format of the key (also known as PEM format, without the header and footer).
   * @return self
   */
  public JWT addCertificate(String algorithm, String cert) {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getBytes(UTF8)));
      List<Crypto> l = cryptoMap.computeIfAbsent(algorithm, k -> new ArrayList<>());
      l.add(new CryptoSignature(ALGORITHM_ALIAS.get(algorithm), certificate, null));
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }

    return this;
  }

  /**
   * Adds a secret (password) for a given JWS algorithm to the crypto map. This is an alternative to using keystores since
   * it is common to see these keys when dealing with 3rd party services such as Google.
   *
   * @param algorithm the JWS algorithm, e.g.: HS256
   * @param key       the base64 DER format of the key (also known as PEM format, without the header and footer).
   * @return self
   */
  public JWT addSecret(String algorithm, String key) {
    if (!MAC_ALGS.contains(algorithm)) {
      throw new RuntimeException("Unknown algorithm: " + algorithm);
    }

    if (key == null) {
      cryptoMap.remove(algorithm);
      return this;
    }

    try {
      final Mac mac = Mac.getInstance(ALGORITHM_ALIAS.get(algorithm));
      mac.init(new SecretKeySpec(key.getBytes(), ALGORITHM_ALIAS.get(algorithm)));

      List<Crypto> l = cryptoMap.computeIfAbsent(algorithm, k -> new ArrayList<>());
      l.add(new CryptoMac(mac));

    } catch (InvalidKeyException | NoSuchAlgorithmException | RuntimeException e) {
      throw new RuntimeException(algorithm + " not supported", e);
    }

    return this;
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
    if (segments.length != (isUnsecure() ? 2 : 3)) {
      throw new RuntimeException("Not enough or too many segments");
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = isUnsecure() ? null : segments[2];

    if ("".equals(signatureSeg)) {
      throw new RuntimeException("Signature is required");
    }

    // base64 decode and parse JSON
    JsonObject header = new JsonObject(new String(base64urlDecode(headerSeg), UTF8));
    JsonObject payload = new JsonObject(new String(base64urlDecode(payloadSeg), UTF8));

    String alg = header.getString("alg");

    List<Crypto> cryptos = cryptoMap.get(alg);

    if (cryptos == null || cryptos.size() == 0) {
      throw new RuntimeException("Algorithm not supported");
    }

    // if we only allow secure alg, then none is not a valid option
    if (!isUnsecure() && "none".equals(alg)) {
      throw new RuntimeException("Algorithm \"none\" not allowed");
    }

    // verify signature. `sign` will return base64 string.
    if (!isUnsecure()) {
      byte[] payloadInput = base64urlDecode(signatureSeg);
      byte[] signingInput = (headerSeg + "." + payloadSeg).getBytes(UTF8);

      for (Crypto c : cryptos) {
        if (c.verify(payloadInput, signingInput)) {
          return payload;
        }
      }

      throw new RuntimeException("Signature verification failed");
    }

    return payload;
  }

  public String sign(JsonObject payload, JsonObject options) {
    final String algorithm = options.getString("algorithm", "HS256");

    List<Crypto> cryptos = cryptoMap.get(algorithm);

    if (cryptos == null || cryptos.size() == 0) {
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
    String signSegment = base64urlEncode(cryptos.get(RND.nextInt(cryptos.size())).sign(signingInput.getBytes(UTF8)));

    return headerSegment + "." + payloadSegment + "." + signSegment;
  }

  private static byte[] base64urlDecode(String str) {
    return decoder.decode(str.getBytes(UTF8));
  }

  private static String base64urlEncode(String str) {
    return base64urlEncode(str.getBytes(UTF8));
  }

  private static String base64urlEncode(byte[] bytes) {
    return encoder.encodeToString(bytes);
  }

  public boolean isUnsecure() {
    return cryptoMap.size() == 1;
  }

  public Collection<String> availableAlgorithms() {
    return cryptoMap.keySet();
  }
}
