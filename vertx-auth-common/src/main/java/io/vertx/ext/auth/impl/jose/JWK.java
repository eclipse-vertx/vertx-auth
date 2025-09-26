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
package io.vertx.ext.auth.impl.jose;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.internal.logging.Logger;
import io.vertx.core.internal.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.asn.ASN1;
import io.vertx.ext.auth.impl.jose.algo.MacSigningAlgorithm;
import io.vertx.ext.auth.impl.jose.algo.PubKeySigningAlgorithm;
import io.vertx.ext.auth.impl.jose.algo.Signer;
import io.vertx.ext.auth.impl.jose.algo.SigningAlgorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.vertx.ext.auth.impl.Codec.base64MimeDecode;
import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;
import static io.vertx.ext.auth.impl.jose.JWS.getSignatureLength;

/**
 * JWK https://tools.ietf.org/html/rfc7517
 * <p>
 * In a nutshell a JWK is a Key(Pair) encoded as JSON. This implementation follows the spec with some limitations:
 * <p>
 * * Supported algorithms are: "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "ES256", "ES256K", "ES384", "ES512", "HS256", "HS384", "HS512", "EdDSA"
 * <p>
 * When working with COSE, then "RS1" is also a valid algorithm.
 * <p>
 * The rationale for this choice is to support the required algorithms for JWT.
 * <p>
 * The constructor takes a single JWK (the the KeySet) or a PEM encoded pair (used by Google and useful for importing
 * standard PEM files from OpenSSL).
 * <p>
 * Certificate chains (x5c) are allowed and verified, certificate urls and fingerprints are not considered.
 *
 * @author Paulo Lopes
 */
public final class JWK {

  static final Logger LOG = LoggerFactory.getLogger(JWK.class);

  // JSON JWK properties
  private final String kid;
  private final String use;

  // the label is a synthetic id that allows comparing 2 keys
  // that are expected to replace each other but are not necessarily
  // the same key cryptographically speaking.
  // In most cases it should be the same as kid, or synthetically generated
  // when there's no kid.
  private final String label;

  // the cryptography objects, not all will be initialized
  private final String kty;
  private final SigningAlgorithm signingAlgorithm;

  public static List<JWK> load(KeyStore keyStore, String keyStorePassword, Map<String, String> passwordProtection) {
    final List<Callable<SigningAlgorithm>> keys = SigningAlgorithm.create(keyStore, keyStorePassword, passwordProtection);
    return keys.stream().flatMap(fact -> {
      try {
        SigningAlgorithm algo = fact.call();
        if (algo instanceof PubKeySigningAlgorithm) {
          PubKeySigningAlgorithm psa = (PubKeySigningAlgorithm) algo;
          return Stream.of(new JWK(psa.name(), psa.id(), psa));
        } else {
          MacSigningAlgorithm msa = (MacSigningAlgorithm) algo;
          return Stream.of(new JWK(msa));
        }
      } catch (Exception e) {
        LOG.warn("Failed to load key for algorithm", e);
        return Stream.empty();
      }
    }).collect(Collectors.toList());
  }

  private static char[] password(String keyStorePassword, Map<String, String> passwordProtection, String alias) {
    String password;
    if (passwordProtection == null || (password = passwordProtection.get(alias)) == null) {
      password = keyStorePassword;
    }
    return password.toCharArray();
  }

  /**
   * Creates a Key(Pair) from pem formatted strings.
   *
   * @param options PEM pub sec key options.
   */
  public JWK(PubSecKeyOptions options) {

    String alg = options.getAlgorithm();
    kid = options.getId();
    use = null;

    final Buffer buffer = Objects.requireNonNull(options.getBuffer());

    label = kid == null ? alg + "#" + buffer.hashCode() : kid;

    // Handle Mac keys

    Mac mac;
    switch (alg) {
      case "HS256":
        try {
          mac = Mac.getInstance("HMacSHA256");
          mac.init(new SecretKeySpec(buffer.getBytes(), "HMacSHA256"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
          throw new RuntimeException(e);
        }
        signingAlgorithm = new MacSigningAlgorithm(alg, mac);
        kty = "oct";
        return;
      case "HS384":
        try {
          mac = Mac.getInstance("HMacSHA384");
          mac.init(new SecretKeySpec(buffer.getBytes(), "HMacSHA384"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
          throw new RuntimeException(e);
        }
        signingAlgorithm = new MacSigningAlgorithm(alg, mac);
        kty = "oct";
        return;
      case "HS512":
        try {
          mac = Mac.getInstance("HMacSHA512");
          mac.init(new SecretKeySpec(buffer.getBytes(), "HMacSHA512"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
          throw new RuntimeException(e);
        }
        signingAlgorithm = new MacSigningAlgorithm(alg, mac);
        kty = "oct";
        return;
    }

    // Handle Pub-Sec Keys
    try {
      switch (alg) {
        case "RS256":
        case "RS384":
        case "RS512":
          kty = "RSA";
          signingAlgorithm = parsePEM(alg, KeyFactory.getInstance("RSA"), buffer.toString(StandardCharsets.US_ASCII));
          break;
        case "PS256":
        case "PS384":
        case "PS512":
          kty = "RSASSA";
          signingAlgorithm = parsePEM(alg, KeyFactory.getInstance("RSA"), buffer.toString(StandardCharsets.US_ASCII));
          break;
        case "ES256":
        case "ES384":
        case "ES512":
        case "ES256K":
          kty = "EC";
          signingAlgorithm = wrapECAlgo(parsePEM(alg, KeyFactory.getInstance("EC"), buffer.toString(StandardCharsets.US_ASCII)));
          break;
        case "EdDSA":
          kty = "EdDSA";
          signingAlgorithm = parsePEM(alg, KeyFactory.getInstance("EdDSA"), buffer.toString(StandardCharsets.US_ASCII));
          break;
        default:
          throw new IllegalArgumentException("Unknown algorithm: " + alg);
      }
    } catch (InvalidKeySpecException | CertificateException | NoSuchAlgorithmException e) {
      // error
      throw new RuntimeException(e);
    }
  }

  private static PubKeySigningAlgorithm parsePEM(String alg, KeyFactory kf, String pem) throws CertificateException, InvalidKeySpecException {
    // extract the information from the pem
    String[] lines = pem.split("\r?\n");
    // A PEM PKCS#8 formatted string shall contain on the first line the kind of content
    if (lines.length <= 2) {
      throw new IllegalArgumentException("PEM contains not enough lines");
    }
    // there must be more than 2 lines
    Pattern begin = Pattern.compile("-----BEGIN (.+?)-----");
    Pattern end = Pattern.compile("-----END (.+?)-----");

    Matcher beginMatcher = begin.matcher(lines[0]);
    if (!beginMatcher.matches()) {
      throw new IllegalArgumentException("PEM first line does not match a BEGIN line");
    }
    String kind = beginMatcher.group(1);
    Buffer buffer = Buffer.buffer();
    boolean endSeen = false;
    for (int i = 1; i < lines.length; i++) {
      if ("".equals(lines[i])) {
        continue;
      }
      Matcher endMatcher = end.matcher(lines[i]);
      if (endMatcher.matches()) {
        endSeen = true;
        if (!kind.equals(endMatcher.group(1))) {
          throw new IllegalArgumentException("PEM END line does not match start");
        }
        break;
      }
      buffer.appendString(lines[i]);
    }

    if (!endSeen) {
      throw new IllegalArgumentException("PEM END line not found");
    }

    PublicKey publicKey;
    PrivateKey privateKey;
    switch (kind) {
      case "CERTIFICATE":
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        publicKey = cf.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))).getPublicKey();
        return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alg, publicKey);
      case "PUBLIC KEY":
      case "PUBLIC RSA KEY":
      case "RSA PUBLIC KEY":
        publicKey = kf.generatePublic(new X509EncodedKeySpec(base64MimeDecode(buffer.getBytes())));
        return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alg, publicKey);
      case "PRIVATE KEY":
      case "PRIVATE RSA KEY":
      case "RSA PRIVATE KEY":
        privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(base64MimeDecode(buffer.getBytes())));
        return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alg, privateKey);
      default:
        throw new IllegalStateException("Invalid PEM content: " + kind);
    }
  }

  private JWK(MacSigningAlgorithm algo) throws NoSuchAlgorithmException {

    kid = null;
    label = algo.name() + "#" + algo.mac().hashCode();
    use = null;
    kty = "oct";

    switch (algo.name()) {
      case "HS256":
      case "HS384":
      case "HS512":
        this.signingAlgorithm = algo;
        break;
      default:
        throw new NoSuchAlgorithmException("Unknown algorithm: " + algo.name());
    }
  }

  private JWK(String algorithm, String id, PubKeySigningAlgorithm algo) throws NoSuchAlgorithmException {

    kid = null;
    label = algo.canSign() ? algorithm + '#' + id + "-" + algo.privateKey().hashCode() : algorithm + '#' + id;
    use = null;

    switch (algorithm) {
      case "RS256":
      case "RS384":
      case "RS512":
        kty = "RSA";
        signingAlgorithm = algo;
        break;
      case "PS256":
      case "PS384":
      case "PS512":
        kty = "RSASSA";
        signingAlgorithm = algo;
        break;
      case "ES256":
      case "ES384":
      case "ES512":
      case "ES256K":
        kty = "EC";
        signingAlgorithm = wrapECAlgo(algo);
        break;
      default:
        throw new NoSuchAlgorithmException("Unknown algorithm: " + algorithm);
    }
  }

  private static SigningAlgorithm wrapECAlgo(PubKeySigningAlgorithm signingAlgo) {
    // JCA EC signatures expect ASN1 formatted signatures
    // while JWS uses it's own format (R+S), while this will be true
    // for all JWS, it may not be true for COSE keys
    return new SigningAlgorithm() {
      @Override
      public String name() {
        return signingAlgo.name();
      }
      @Override
      public String id() {
        return signingAlgo.id();
      }
      @Override
      public boolean canSign() {
        return signingAlgo.canSign();
      }
      @Override
      public boolean canVerify() {
        return signingAlgo.canVerify();
      }
      @Override
      public io.vertx.ext.auth.impl.jose.algo.Signer signer() throws GeneralSecurityException {
        io.vertx.ext.auth.impl.jose.algo.Signer signer = signingAlgo.signer();
        int len = getSignatureLength(signingAlgo.name(), signingAlgo.publicKey());
        return new Signer() {
          @Override
          public byte[] sign(byte[] data) throws GeneralSecurityException {
            return JWS.toJWS(signer.sign(data), len);
          }
          @Override
          public boolean verify(byte[] expected, byte[] payload) throws GeneralSecurityException {
            if (!JWS.isASN1(expected)) {
              expected = JWS.toASN1(expected);
            }
            return signer.verify(expected, payload);
          }
        };
      }
    };
  }

  public JWK(JsonObject json) {
    kid = json.getString("kid");
    use = json.getString("use");

    String alg;
    try {
      switch (json.getString("kty")) {
        case "RSA":
        case "RSASSA":
          kty = json.getString("kty");
          // get the alias for the algorithm
          alg = json.getString("alg", "RS256");

          switch (alg) {
            case "RS1":
              // special case for COSE
            case "RS256":
            case "RS384":
            case "RS512":
            case "PS256":
            case "PS384":
            case "PS512":
              signingAlgorithm = createRSA(alg, json);
              break;
            default:
              throw new NoSuchAlgorithmException(alg);
          }
          break;
        case "EC":
          kty = json.getString("kty");
          // get the alias for the algorithm
          alg = json.getString("alg", "ES256");

          switch (alg) {
            case "ES256":
            case "ES256K":
            case "ES512":
            case "ES384":
              signingAlgorithm = wrapECAlgo(createEC(alg, json));
              break;
            default:
              throw new NoSuchAlgorithmException(alg);
          }
          break;
        case "OKP":
          kty = json.getString("kty");
          // get the alias for the algorithm
          alg = json.getString("alg", "EdDSA");
          signingAlgorithm = createOKP(alg, json);
          break;
        case "oct":
          kty = json.getString("kty");
          // get the alias for the algorithm
          alg = json.getString("alg", "HS256");

          switch (alg) {
            case "HS256":
              signingAlgorithm = createOCT(alg, "HMacSHA256", json);
              break;
            case "HS384":
              signingAlgorithm = createOCT(alg, "HMacSHA384", json);
              break;
            case "HS512":
              signingAlgorithm = createOCT(alg, "HMacSHA512", json);
              break;
            default:
              throw new NoSuchAlgorithmException(alg);
          }
          break;

        default:
          throw new RuntimeException("Unsupported key type: " + json.getString("kty"));
      }

      label = kid != null ? kid : alg + "#" + json.hashCode();

    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | InvalidParameterSpecException |
             CertificateException | NoSuchProviderException | SignatureException e) {
      throw new RuntimeException(e);
    }
  }

  private static PubKeySigningAlgorithm createRSA(String alg, JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException {
    PublicKey publicKey = null;
    PrivateKey privateKey = null;
    // public key
    if (jsonHasProperties(json, "n", "e")) {
      final BigInteger n = new BigInteger(1, base64UrlDecode(json.getString("n")));
      final BigInteger e = new BigInteger(1, base64UrlDecode(json.getString("e")));
      publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
      // private key
      if (jsonHasProperties(json, "d", "p", "q", "dp", "dq", "qi")) {
        final BigInteger d = new BigInteger(1, base64UrlDecode(json.getString("d")));
        final BigInteger p = new BigInteger(1, base64UrlDecode(json.getString("p")));
        final BigInteger q = new BigInteger(1, base64UrlDecode(json.getString("q")));
        final BigInteger dp = new BigInteger(1, base64UrlDecode(json.getString("dp")));
        final BigInteger dq = new BigInteger(1, base64UrlDecode(json.getString("dq")));
        final BigInteger qi = new BigInteger(1, base64UrlDecode(json.getString("qi")));

        privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi));
      }
    }

    // certificate chain
    if (json.containsKey("x5c")) {
      JsonArray x5c = json.getJsonArray("x5c");

      List<X509Certificate> certChain = new ArrayList<>();
      for (int i = 0; i < x5c.size(); i++) {
        certChain.add(JWS.parseX5c(x5c.getString(i)));
      }

      // validate the chain (don't assume the chain includes the root CA certificate
      CertificateHelper.checkValidity(certChain, false, null);

      final X509Certificate certificate = certChain.get(0);

      // extract the public key
      publicKey = certificate.getPublicKey();
    }

    if (publicKey != null || privateKey != null) {
      return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alg, privateKey, publicKey);
    }
    return null;
  }

  private static PubKeySigningAlgorithm createEC(String alg, JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(translateECCrv(json.getString("crv"))));

    // public key
    PublicKey publicKey = null;
    if (jsonHasProperties(json, "x", "y")) {
      final BigInteger x = new BigInteger(1, base64UrlDecode(json.getString("x")));
      final BigInteger y = new BigInteger(1, base64UrlDecode(json.getString("y")));
      publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), parameters.getParameterSpec(ECParameterSpec.class)));
    }

    // private key
    PrivateKey privateKey = null;
    if (jsonHasProperties(json, "d")) {
      final BigInteger d = new BigInteger(1, base64UrlDecode(json.getString("d")));
      privateKey = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, parameters.getParameterSpec(ECParameterSpec.class)));
    }

    if (publicKey != null || privateKey != null) {
      return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alg, privateKey, publicKey);
    }

    return null;
  }

  private static PubKeySigningAlgorithm createOKP(String alg, JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException {
    // public key
    PublicKey publicKey;
    if (jsonHasProperties(json, "x")) {
      final byte[] key = base64UrlDecode(json.getString("x"));
      final byte bitStringTag = (byte) 0x3;

      //  SPKI ::= SEQUENCE {
      //       algorithm   SEQUENCE {
      //            oid = id-ecPublicKey {1 2 840 10045 2}
      //            namedCurve = oid for algorithm
      //       }
      //       subjectPublicKey BIT STRING CONTAINS  key bytes
      //  }

      byte[] spki = ASN1.sequence(
        Buffer.buffer()
          .appendBytes(ASN1.sequence(oidCrv(json.getString("crv"))))
          .appendByte(bitStringTag)
          .appendBytes(ASN1.length(key.length + 1))
          .appendByte((byte) 0x00)
          .appendBytes(key)
          .getBytes());

      publicKey = KeyFactory.getInstance("EdDSA").generatePublic(new X509EncodedKeySpec(spki));
    } else {
      publicKey = null;
    }

    // private key
    PrivateKey privateKey;
    if (jsonHasProperties(json, "d")) {
      final byte[] key = base64UrlDecode(json.getString("d"));
      final byte octetStringTag = (byte) 0x4;

      byte[] asnKey = Buffer.buffer()
        .appendByte(octetStringTag)
        .appendBytes(ASN1.length(key.length))
        .appendBytes(key)
        .getBytes();

      //  PKCS#8 ::= SEQUENCE {
      //     version INTEGER {0}
      //      privateKeyALgorithm SEQUENCE {
      //           algorithm OID,
      //           parameters ANY
      //      }
      //     privateKey ECPrivateKey,
      //     attributes [0] IMPLICIT Attributes OPTIONAL
      //     publicKey [1] IMPLICIT BIT STRING OPTIONAL
      //   }

      byte[] pkcs8 = ASN1.sequence(
        Buffer.buffer()
          .appendBytes(new byte[]{2, 1, 0})
          .appendBytes(ASN1.sequence(oidCrv(json.getString("crv"))))
          .appendByte(octetStringTag)
          .appendBytes(ASN1.length(asnKey.length))
          .appendBytes(asnKey)
          .getBytes()
      );

      privateKey = KeyFactory.getInstance("EdDSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    } else {
      privateKey = null;
    }

    if (publicKey != null || privateKey != null) {
      return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alg, privateKey, publicKey);
    } else {
      return null;
    }
  }

  private static SigningAlgorithm createOCT(String name, String alias, JsonObject json) throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = Mac.getInstance(alias);
    mac.init(new SecretKeySpec(base64UrlDecode(json.getString("k")), alias));
    return new MacSigningAlgorithm(name, mac);
  }

  public String getAlgorithm() {
    return signingAlgorithm != null ? signingAlgorithm.name() : null;
  }

  public String getId() {
    return kid;
  }

  private static String translateECCrv(String crv) {
    switch (crv) {
      case "P-256":
        return "secp256r1";
      case "P-384":
        return "secp384r1";
      case "P-521":
        return "secp521r1";
      case "secp256k1":
        return "secp256k1";
      default:
        throw new IllegalArgumentException("Unsupported {crv}: " + crv);
    }
  }

  private static byte[] oidCrv(String crv) {
    switch (crv) {
      case "Ed25519":
        // 1.3.101.112
        return new byte[]{0x6, 0x3, 0x2b, 101, 112};
      case "Ed448":
        // 1.3.101.113
        return new byte[]{0x6, 0x3, 0x2b, 101, 113};
      case "X25519":
        // 1.3.101.110
        return new byte[]{0x6, 3, 0x2b, 101, 110};
      case "X448":
        // 1.3.101.111
        return new byte[]{0x6, 3, 0x2b, 101, 111};
      default:
        throw new IllegalArgumentException("Unsupported {crv}: " + crv);
    }
  }


  private static boolean jsonHasProperties(JsonObject json, String... properties) {
    for (String property : properties) {
      if (!json.containsKey(property) || json.getValue(property) == null) {
        return false;
      }
    }

    return true;
  }

  public String use() {
    return use;
  }

  public String label() {
    return label;
  }

  public String kty() {
    return kty;
  }

  public SigningAlgorithm signingAlgorithm() {
    return signingAlgorithm;
  }

  public PublicKey publicKey() {
    return signingAlgorithm instanceof PubKeySigningAlgorithm ? ((PubKeySigningAlgorithm)signingAlgorithm).publicKey() : null;
  }

  public PrivateKey privateKey() {
    return signingAlgorithm instanceof PubKeySigningAlgorithm ? ((PubKeySigningAlgorithm)signingAlgorithm).privateKey() : null;
  }
}
