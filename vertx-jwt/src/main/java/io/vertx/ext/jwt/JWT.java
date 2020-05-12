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

import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * JWT and JWS implementation draft-ietf-oauth-json-web-token-32.
 *
 * @author Paulo Lopes
 */
public final class JWT {

  private final Logger logger = LoggerFactory.getLogger(JWT.class);

  // simple random as its value is just to create entropy
  private static final Random RND = new Random();

  private static final Charset UTF8 = StandardCharsets.UTF_8;

  // as described in the terminology section: https://tools.ietf.org/html/rfc7515#section-2
  private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder decoder = Base64.getUrlDecoder();

  // keep 2 maps (1 for encode, 1 for decode)
  private final Map<String, List<Crypto>> SIGN = new ConcurrentHashMap<>();
  private final Map<String, List<Crypto>> VERIFY = new ConcurrentHashMap<>();

  public JWT() {
    // Spec requires "none" to always be available
    SIGN.put("none", Collections.singletonList(new CryptoNone()));
    VERIFY.put("none", Collections.singletonList(new CryptoNone()));
  }

  /**
   * Loads all keys from a keystore.
   * @deprecated Use {@link JWK#load(KeyStore, String, Map)} instead.
   * @param keyStore the keystore to load
   * @param keyStorePassword the keystore password
   */
  @Deprecated
  public JWT(final KeyStore keyStore, final char[] keyStorePassword) {
    this();
    // delegate to the JWK loader
    for (JWK key : JWK.load(keyStore, new String(keyStorePassword), null)) {
      addJWK(key);
    }
  }

  /**
   * Adds a JSON Web Key (rfc7517) to the crypto map.
   *
   * @param jwk a JSON Web Key
   * @return self
   */
  public JWT addJWK(JWK jwk) {

    List<Crypto> current = null;

    if (jwk.isFor(JWK.USE_ENC)) {
      current = VERIFY.computeIfAbsent(jwk.getAlgorithm(), k -> new ArrayList<>());
      addJWK(current, jwk);
    }

    if (jwk.isFor(JWK.USE_SIG)) {
      current = SIGN.computeIfAbsent(jwk.getAlgorithm(), k -> new ArrayList<>());
      addJWK(current, jwk);
    }

    if (current == null) {
      throw new IllegalStateException("unknown JWK use: " + jwk.getUse());
    }

    return this;
  }

  private void addJWK(List<Crypto> current, JWK jwk) {
    boolean replaced = false;
    for (int i = 0; i < current.size(); i++) {
      if (current.get(i).getLabel().equals(jwk.getLabel())) {
        // replace
        current.set(i, jwk);
        replaced = true;
        break;
      }
    }

    if (!replaced) {
      // non existent, add it!
      current.add(jwk);
    }
  }

  public static JsonObject parse(final byte[] token) {
    return parse(new String(token, UTF8));
  }

  public static JsonObject parse(final String token) {
    String[] segments = token.split("\\.");
    if (segments.length < 2 || segments.length > 3) {
      throw new RuntimeException("Not enough or too many segments");
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = segments.length == 2 ? null : segments[2];

    // base64 decode and parse JSON
    JsonObject header = new JsonObject(new String(base64urlDecode(headerSeg), UTF8));
    JsonObject payload = new JsonObject(new String(base64urlDecode(payloadSeg), UTF8));

    return new JsonObject()
      .put("header", header)
      .put("payload", payload)
      .put("signatureBase", (headerSeg + "." + payloadSeg))
      .put("signature", signatureSeg);
  }

  public JsonObject decode(final String token) {
    // lock the secure state
    final boolean unsecure = isUnsecure();
    String[] segments = token.split("\\.");

    if (unsecure) {
      if (segments.length != 2) {
        throw new IllegalStateException("JWT is in unsecured mode but token is signed.");
      }
    } else {
      if (segments.length != 3) {
        throw new IllegalStateException("JWT is in secure mode but token is not signed.");
      }
    }

    // All segment should be base64
    String headerSeg = segments[0];
    String payloadSeg = segments[1];
    String signatureSeg = unsecure ? null : segments[2];

    if ("".equals(signatureSeg)) {
      throw new IllegalStateException("Signature is required");
    }

    // base64 decode and parse JSON
    JsonObject header = new JsonObject(new String(base64urlDecode(headerSeg), UTF8));
    JsonObject payload = new JsonObject(new String(base64urlDecode(payloadSeg), UTF8));

    String alg = header.getString("alg");

    List<Crypto> cryptos = VERIFY.get(alg);

    if (cryptos == null || cryptos.size() == 0) {
      throw new NoSuchKeyIdException(alg);
    }

    // if we only allow secure alg, then none is not a valid option
    if (!unsecure && "none".equals(alg)) {
      throw new IllegalStateException("Algorithm \"none\" not allowed");
    }

    // verify signature. `sign` will return base64 string.
    if (!unsecure) {
      byte[] payloadInput = base64urlDecode(signatureSeg);
      byte[] signingInput = (headerSeg + "." + payloadSeg).getBytes(UTF8);

      String kid = header.getString("kid");
      boolean hasKey = false;

      for (Crypto c : cryptos) {
        // if a token has a kid and it doesn't match the crypto id skip it
        if (kid != null && c.getId() != null && !kid.equals(c.getId())) {
          continue;
        }
        // signal that this object crypto's list has the required key
        hasKey = true;
        if (c.verify(payloadInput, signingInput)) {
          return payload;
        }
      }

      if (hasKey) {
        throw new RuntimeException("Signature verification failed");
      } else {
        throw new NoSuchKeyIdException(alg, kid);
      }
    }

    return payload;
  }

  public boolean isExpired(JsonObject jwt, JWTOptions options) {

    if (jwt == null) {
      return false;
    }

    // All dates in JWT are of type NumericDate
    // a NumericDate is: numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until
    // the specified UTC date/time, ignoring leap seconds
    final long now = (System.currentTimeMillis() / 1000);

    if (jwt.containsKey("exp") && !options.isIgnoreExpiration()) {
      if (now - options.getLeeway() >= jwt.getLong("exp")) {
        if (logger.isTraceEnabled()) {
          logger.trace(String.format("Expired JWT token: exp[%d] <= (now[%d] - leeway[%d])", jwt.getLong("exp"), now, options.getLeeway()));
        }
        return true;
      }
    }

    if (jwt.containsKey("iat")) {
      Long iat = jwt.getLong("iat");
      // issue at must be in the past
      if (iat > now + options.getLeeway()) {
        if (logger.isTraceEnabled()) {
          logger.trace(String.format("Invalid JWT token: iat[%d] > now[%d] + leeway[%d]", iat, now, options.getLeeway()));
        }
        return true;
      }
    }

    if (jwt.containsKey("nbf")) {
      Long nbf = jwt.getLong("nbf");
      // not before must be after now
      if (nbf > now + options.getLeeway()) {
        if (logger.isTraceEnabled()) {
          logger.trace(String.format("Invalid JWT token: nbf[%d] > now[%d] + leeway[%d]", nbf, now, options.getLeeway()));
        }
        return true;
      }
    }

    return false;
  }

  /**
   * Scope claim are used to grant access to a specific resource.
   * They are included into the JWT when the user consent access to the resource,
   * or sometimes without user consent (bypass approval).
   * @param jwt JsonObject decoded json web token value.
   * @param options JWTOptions coming from the provider.
   * @return true if required scopes are into the JWT.
   */
  public boolean isScopeGranted(JsonObject jwt, JWTOptions options) {

    if(jwt == null) {
      return false;
    }

    if(options.getScopes() == null || options.getScopes().isEmpty()) {
      return true; // no scopes to check
    }

    if(jwt.getValue("scope") == null) {
      if (logger.isDebugEnabled()) {
        logger.debug("Invalid JWT: scope claim is required");
      }
      return false;
    }

    JsonArray target;
    if (jwt.getValue("scope") instanceof String) {
      target = new JsonArray(
        Stream.of(jwt.getString("scope")
          .split(options.getScopeDelimiter()))
          .collect(Collectors.toList())
      );
    } else {
      target = jwt.getJsonArray("scope");
    }

    if(!target.getList().containsAll(options.getScopes())) {
      if (logger.isDebugEnabled()) {
        logger.debug(String.format("Invalid JWT scopes expected[%s] actual[%s]", options.getScopes(), target.getList()));
      }
      return false;
    }

    return true;
  }

  public String sign(JsonObject payload, JWTOptions options) {
    final String algorithm = options.getAlgorithm();

    List<Crypto> cryptos = SIGN.get(algorithm);

    if (cryptos == null || cryptos.size() == 0) {
      throw new RuntimeException("Algorithm not supported: " + algorithm);
    }

    // lock the crypto implementation
    final Crypto crypto = cryptos.get(RND.nextInt(cryptos.size()));

    // header, typ is fixed value.
    JsonObject header = new JsonObject()
      .mergeIn(options.getHeader())
      .put("typ", "JWT")
      .put("alg", algorithm);

    // add kid if present
    if (crypto.getId() != null) {
      header.put("kid", crypto.getId());
    }

    // NumericDate is a number is seconds since 1st Jan 1970 in UTC
    long timestamp = System.currentTimeMillis() / 1000;

    if (!options.isNoTimestamp()) {
      payload.put("iat", payload.getValue("iat", timestamp));
    }

    if (options.getExpiresInSeconds() > 0) {
      payload.put("exp", timestamp + options.getExpiresInSeconds());
    }

    if (options.getAudience() != null && options.getAudience().size() >= 1) {
      if (options.getAudience().size() > 1) {
        payload.put("aud", new JsonArray(options.getAudience()));
      } else {
        payload.put("aud", options.getAudience().get(0));
      }
    }

    if(options.getScopes() != null && options.getScopes().size() >= 1) {
      if(options.hasScopeDelimiter()) {
        payload.put("scope", String.join(options.getScopeDelimiter(), options.getScopes()));
      } else {
        payload.put("scope", new JsonArray(options.getScopes()));
      }
    }

    if (options.getIssuer() != null) {
      payload.put("iss", options.getIssuer());
    }

    if (options.getSubject() != null) {
      payload.put("sub", options.getSubject());
    }

    // create segments, all segment should be base64 string
    String headerSegment = base64urlEncode(header.encode());
    String payloadSegment = base64urlEncode(payload.encode());
    String signingInput = headerSegment + "." + payloadSegment;
    String signSegment = base64urlEncode(crypto.sign(signingInput.getBytes(UTF8)));

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
    return VERIFY.size() == 1 && SIGN.size() == 1;
  }

  public Collection<String> availableAlgorithms() {
    Set<String> algorithms = new HashSet<>();

    algorithms.addAll(VERIFY.keySet());
    algorithms.addAll(SIGN.keySet());

    return algorithms;
  }
}
