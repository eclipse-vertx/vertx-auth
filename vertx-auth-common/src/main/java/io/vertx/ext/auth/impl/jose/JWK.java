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
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.impl.CertificateHelper;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JWK https://tools.ietf.org/html/rfc7517
 * <p>
 * In a nutshell a JWK is a Key(Pair) encoded as JSON. This implementation follows the spec with some limitations:
 * <p>
 * * Supported algorithms are: "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "ES256", "ES256K", "ES384", "ES512", "HS256", "HS384", "HS512"
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
public final class JWK implements Crypto {

  public static final int USE_SIG = 1;
  public static final int USE_ENC = 2;

  private static final Charset UTF8 = StandardCharsets.UTF_8;
  private static final Logger LOG = LoggerFactory.getLogger(JWK.class);

  // JSON JWK properties
  private final String kid;
  private final String alg;
  private final String kty;

  // the label is a synthetic id that allows comparing 2 keys
  // that are expected to replace each other but are not necessarely
  // the same key cryptographically speaking.
  // In most cases it should be the same as kid, or synthetically generated
  // when there's no kid.
  private final String label;

  // the length of the signature. This is derived from the algorithm name
  // this will help to cope with signatures that are longer (yet valid) than
  // the expected result
  private final int len;

  // if a key is marked as symmetric it can be used interchangeably
  private final boolean symmetric;

  // verify/sign mode
  private final int use;

  // the cryptography objects, not all will be initialized
  private PrivateKey privateKey;
  private PublicKey publicKey;
  private Signature signature;
  private Cipher cipher;
  private Mac mac;

  public static List<JWK> load(KeyStore keyStore, String keyStorePassword, Map<String, String> passwordProtection) {

    Map<String, String> aliases = new HashMap<String, String>() {{
      put("HS256", "HMacSHA256");
      put("HS384", "HMacSHA384");
      put("HS512", "HMacSHA512");
      put("RS256", "SHA256withRSA");
      put("RS384", "SHA384withRSA");
      put("RS512", "SHA512withRSA");
      put("ES256K", "SHA256withECDSA");
      put("ES256", "SHA256withECDSA");
      put("ES384", "SHA384withECDSA");
      put("ES512", "SHA512withECDSA");
    }};

    final List<JWK> keys = new ArrayList<>();

    // load MACs
    for (String alias : Arrays.asList("HS256", "HS384", "HS512")) {
      try {
        final Key secretKey = keyStore.getKey(alias, keyStorePassword.toCharArray());
        // key store does not have the requested algorithm
        if (secretKey == null) {
          continue;
        }
        // test the algorithm
        String alg = secretKey.getAlgorithm();
        // the algorithm cannot be null and it cannot be different from
        // the alias list
        final String expected = aliases.get(alias);
        if (alg == null || !alg.equalsIgnoreCase(expected)) {
          LOG.warn("The key algorithm does not match " + expected);
          continue;
        }
        // algorithm is valid
        Mac mac = Mac.getInstance(alg);
        mac.init(secretKey);
        keys.add(new JWK(alias, mac));
      } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException e) {
        LOG.warn("Failed to load key for algorithm: " + alias, e);
      }
    }

    for (String alias : Arrays.asList("RS256", "RS384", "RS512", "ES256K", "ES256", "ES384", "ES512")) {
      try {
        // Key pairs on keystores are stored with a certificate, so we use it to load a key pair
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        // not found
        if (certificate == null) {
          continue;
        }
        // start validation
        certificate.checkValidity();
        // verify that the algorithms match
        String alg = certificate.getSigAlgName();
        // the algorithm cannot be null and it cannot be different from
        // the alias list
        final String expected = aliases.get(alias);
        if (alg == null || !alg.equalsIgnoreCase(expected)) {
          LOG.warn("The key algorithm does not match " + expected);
          continue;
        }
        // algorithm is valid
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, passwordProtection == null ? keyStorePassword.toCharArray() : passwordProtection.get(alias).toCharArray());
        keys.add(new JWK(alias, certificate, privateKey));
      } catch (ClassCastException | KeyStoreException | CertificateExpiredException | CertificateNotYetValidException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidAlgorithmParameterException e) {
        LOG.warn("Failed to load key for algorithm: " + alias, e);
      }
    }

    return keys;
  }

  /**
   * Creates a Key(Pair) from pem formatted strings.
   *
   * @param options PEM pub sec key options.
   */
  public JWK(PubSecKeyOptions options) {

    alg = options.getAlgorithm();
    kid = options.getId();

    final String pem = Objects.requireNonNull(options.getBuffer());

    label = kid == null ? alg + "#" + pem.hashCode() : kid;

    // Handle Mac keys

    switch (alg) {
      case "HS256":
        try {
          mac = Mac.getInstance("HMacSHA256");
          mac.init(new SecretKeySpec(pem.getBytes(), "HMacSHA256"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
          throw new RuntimeException(e);
        }
        kty = "oct";
        len = 256;
        // this is a symmetric key
        symmetric = true;
        use = USE_SIG + USE_ENC;
        return;
      case "HS384":
        try {
          mac = Mac.getInstance("HMacSHA384");
          mac.init(new SecretKeySpec(pem.getBytes(), "HMacSHA384"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
          throw new RuntimeException(e);
        }
        kty = "oct";
        len = 384;
        // this is a symmetric key
        symmetric = true;
        use = USE_SIG + USE_ENC;
        return;
      case "HS512":
        try {
          mac = Mac.getInstance("HMacSHA512");
          mac.init(new SecretKeySpec(pem.getBytes(), "HMacSHA512"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
          throw new RuntimeException(e);
        }
        kty = "oct";
        len = 512;
        // this is a symmetric key
        symmetric = true;
        use = USE_SIG + USE_ENC;
        return;
    }

    // Handle Pub-Sec Keys

    symmetric = false;

    try {
      switch (alg) {
        case "RS256":
        case "RS384":
        case "RS512":
          kty = "RSA";
          use = parsePEM(KeyFactory.getInstance("RSA"), pem);
          signature = JWS.getSignature(alg);
          len = JWS.getSignatureLength(alg, publicKey);
          break;
        case "PS256":
        case "PS384":
        case "PS512":
          kty = "RSASSA";
          use = parsePEM(KeyFactory.getInstance("RSA"), pem);
          signature = JWS.getSignature(alg);
          len = JWS.getSignatureLength(alg, publicKey);
          break;
        case "ES256":
        case "ES384":
        case "ES512":
        case "ES256K":
          kty = "EC";
          len = JWS.getSignatureLength(alg, publicKey);
          use = parsePEM(KeyFactory.getInstance("EC"), pem);
          signature = JWS.getSignature(alg);
          break;
        default:
          throw new IllegalArgumentException("Unknown algorithm: " + alg);
      }
    } catch (InvalidKeySpecException | CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      // error
      throw new RuntimeException(e);
    }
  }

  private int parsePEM(KeyFactory kf, String pem) throws CertificateException, InvalidKeySpecException {
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

    switch (kind) {
      case "CERTIFICATE":
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        publicKey = cf.generateCertificate(new ByteArrayInputStream(pem.getBytes())).getPublicKey();
        return USE_ENC;
      case "PUBLIC KEY":
      case "PUBLIC RSA KEY":
        publicKey = kf.generatePublic(new X509EncodedKeySpec(Base64.getMimeDecoder().decode(buffer.getBytes())));
        return USE_ENC;
      case "PRIVATE KEY":
      case "PRIVATE RSA KEY":
        privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(buffer.getBytes())));
        return USE_SIG;
      default:
        throw new IllegalStateException("Invalid PEM content: " + kind);
    }
  }

  private JWK(String algorithm, Mac mac) throws NoSuchAlgorithmException {

    alg = algorithm;
    kid = null;
    label = alg + "#" + mac.hashCode();
    // this is a symmetric key
    symmetric = true;
    use = USE_SIG + USE_ENC;

    // test the algorithm
    String macAlg = mac.getAlgorithm();

    switch (alg) {
      case "HS256":
        kty = "oct";
        len = 256;
        if (!"HMacSHA256".equalsIgnoreCase(macAlg)) {
          throw new IllegalArgumentException("The key algorithm does not match, expected: HMacSHA256");
        }
        this.mac = mac;
        break;
      case "HS384":
        kty = "oct";
        len = 384;
        if (!"HMacSHA384".equalsIgnoreCase(macAlg)) {
          throw new IllegalArgumentException("The key algorithm does not match, expected: HMacSHA384");
        }
        this.mac = mac;
        break;
      case "HS512":
        kty = "oct";
        len = 512;
        if (!"HMacSHA512".equalsIgnoreCase(macAlg)) {
          throw new IllegalArgumentException("The key algorithm does not match, expected: HMacSHA512");
        }
        this.mac = mac;
        break;
      default:
        throw new NoSuchAlgorithmException("Unknown algorithm: " + algorithm);
    }
  }

  private JWK(String algorithm, X509Certificate certificate, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

    alg = algorithm;
    kid = null;
    label = privateKey != null ? algorithm + '#' + certificate.hashCode() + "-" + privateKey.hashCode() : algorithm + '#' + certificate.hashCode();
    symmetric = false;

    this.publicKey = certificate.getPublicKey();
    this.privateKey = privateKey;

    // this key does both because we have a certificate (public) + private key ?
    if (privateKey != null) {
      use = USE_ENC + USE_SIG;
    } else {
      use = USE_ENC;
    }

    switch (algorithm) {
      case "RS256":
      case "RS384":
      case "RS512":
        kty = "RSA";
        signature = JWS.getSignature(alg);
        len = JWS.getSignatureLength(alg, publicKey);
        break;
      case "PS256":
      case "PS384":
      case "PS512":
        kty = "RSASSA";
        signature = JWS.getSignature(alg);
        len = JWS.getSignatureLength(alg, publicKey);
        break;
      case "ES256":
      case "ES384":
      case "ES512":
      case "ES256K":
        kty = "EC";
        len = JWS.getSignatureLength(alg, publicKey);
        signature = JWS.getSignature(alg);
        break;
      default:
        throw new NoSuchAlgorithmException("Unknown algorithm: " + algorithm);
    }
  }

  public JWK(JsonObject json) {
    kid = json.getString("kid");

    try {
      switch (json.getString("kty")) {
        case "RSA":
        case "RSASSA":
          kty = json.getString("kty");
          // get the alias for the algorithm
          alg = json.getString("alg", "RS256");
          symmetric = false;

          switch (alg) {
            case "RS1":
              // special case for COSE
            case "RS256":
            case "RS384":
            case "RS512":
            case "PS256":
            case "PS384":
            case "PS512":
              use = createRSA(json);
              len = JWS.getSignatureLength(alg, publicKey);
              break;
            default:
              throw new NoSuchAlgorithmException(alg);
          }
          break;
        case "EC":
          kty = json.getString("kty");
          // get the alias for the algorithm
          alg = json.getString("alg", "ES256");
          symmetric = false;

          switch (alg) {
            case "ES256":
            case "ES256K":
            case "ES512":
            case "ES384":
              len = JWS.getSignatureLength(alg, publicKey);
              use = createEC(json);
              break;
            default:
              throw new NoSuchAlgorithmException(alg);
          }
          break;
//        case "OKP":
//          kty = json.getString("kty");
//          // get the alias for the algorithm
//          alg = json.getString("alg", "EdDSA");
//          symmetric = false;
//          break;
        case "oct":
          kty = json.getString("kty");
          // get the alias for the algorithm
          alg = json.getString("alg", "HS256");
          symmetric = true;

          switch (alg) {
            case "HS256":
              len = 256;
              use = createOCT("HMacSHA256", json);
              break;
            case "HS384":
              len = 384;
              use = createOCT("HMacSHA384", json);
              break;
            case "HS512":
              len = 512;
              use = createOCT("HMacSHA512", json);
              break;
            default:
              throw new NoSuchAlgorithmException(alg);
          }
          break;

        default:
          throw new RuntimeException("Unsupported key type: " + json.getString("kty"));
      }

      label = kid != null ? kid : alg + "#" + json.hashCode();

    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | InvalidParameterSpecException | CertificateException | NoSuchPaddingException | NoSuchProviderException | SignatureException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  private int createRSA(JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException, SignatureException {
    int use = 0;

    // public key
    if (jsonHasProperties(json, "n", "e")) {
      final BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("n")));
      final BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("e")));
      publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
      if ((use & USE_ENC) == 0) {
        use += USE_ENC;
      }
    }

    // private key
    if (jsonHasProperties(json, "n", "e", "d", "p", "q", "dp", "dq", "qi")) {
      final BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("n")));
      final BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("e")));
      final BigInteger d = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("d")));
      final BigInteger p = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("p")));
      final BigInteger q = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("q")));
      final BigInteger dp = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("dp")));
      final BigInteger dq = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("dq")));
      final BigInteger qi = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("qi")));

      privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi));
      if ((use & USE_SIG) == 0) {
        use += USE_SIG;
      }
    }

    // certificate chain
    if (json.containsKey("x5c")) {
      JsonArray x5c = json.getJsonArray("x5c");

      List<X509Certificate> certChain = new ArrayList<>();
      for (int i = 0; i < x5c.size(); i++) {
        certChain.add(JWS.parseX5c(addBoundaries(x5c.getString(i)).getBytes(UTF8)));
      }

      // validate the chain (don't assume the chain includes the root CA certificate
      CertificateHelper.checkValidity(certChain, false);

      final X509Certificate certificate = certChain.get(0);

      // extract the public key
      publicKey = certificate.getPublicKey();
      if ((use & USE_ENC) == 0) {
        use += USE_ENC;
      }
    }

    switch (json.getString("use", "sig")) {
      case "sig":
        try {
          // use default
          signature = JWS.getSignature(alg);
          if (json.containsKey("use")) {
            if ((use & USE_SIG) == 0) {
              use += USE_SIG;
            }
          }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
          // error
          throw new RuntimeException(e);
        }
        break;
      case "enc":
        cipher = Cipher.getInstance("RSA");
        if (json.containsKey("use")) {
          if ((use & USE_ENC) == 0) {
            use += USE_ENC;
          }
        }
    }

    return use;
  }

  private String addBoundaries(final String certificate) {
    return "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----\n";
  }

  private int createEC(JsonObject json) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    int use = 0;
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(translate(json.getString("crv"))));

    // public key
    if (jsonHasProperties(json, "x", "y")) {
      final BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("x")));
      final BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("y")));
      publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), parameters.getParameterSpec(ECParameterSpec.class)));
      if ((use & USE_ENC) == 0) {
        use += USE_ENC;
      }
    }

    // private key
    if (jsonHasProperties(json, "x", "y", "d")) {
      final BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("x")));
      final BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("y")));
      final BigInteger d = new BigInteger(1, Base64.getUrlDecoder().decode(json.getString("d")));
      privateKey = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, parameters.getParameterSpec(ECParameterSpec.class)));
      if ((use & USE_SIG) == 0) {
        use += USE_SIG;
      }
    }

    switch (json.getString("use", "sig")) {
      case "sig":
        signature = JWS.getSignature(alg);
        if (json.containsKey("use")) {
          if ((use & USE_SIG) == 0) {
            use += USE_SIG;
          }
        }
        break;
      case "enc":
        cipher = Cipher.getInstance("EC");
        if (json.containsKey("use")) {
          if ((use & USE_ENC) == 0) {
            use += USE_ENC;
          }
        }
        break;
    }

    return use;
  }

  private int createOCT(String alias, JsonObject json) throws NoSuchAlgorithmException, InvalidKeyException {
    mac = Mac.getInstance(alias);
    mac.init(new SecretKeySpec(json.getBinary("k"), alias));
    return USE_SIG + USE_ENC;
  }

  public String getAlgorithm() {
    return alg;
  }

  public String getId() {
    return kid;
  }

  public Key unwrap() {
    if (privateKey != null) {
      return privateKey;
    }
    if (publicKey != null) {
      return publicKey;
    }
    return null;
  }

  public synchronized byte[] encrypt(byte[] payload) {
    if (cipher == null) {
      throw new RuntimeException("Key use is not 'enc'");
    }

    try {
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      cipher.update(payload);
      return cipher.doFinal();
    } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized byte[] decrypt(byte[] payload) {
    if (cipher == null) {
      throw new RuntimeException("Key use is not 'enc'");
    }

    try {
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      cipher.update(payload);
      return cipher.doFinal();
    } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    if (!isFor(USE_SIG)) {
      throw new IllegalStateException("Key use is not 'sig'");
    }

    if (symmetric) {
      return mac.doFinal(payload);
    } else {
      try {
        signature.initSign(privateKey);
        signature.update(payload);
        byte[] sig = signature.sign();
        switch (kty) {
          case "EC":
            return JWS.toJWS(sig, len);
          default:
            return sig;
        }
      } catch (SignatureException | InvalidKeyException e) {
        throw new RuntimeException(e);
      }
    }
  }

  @Override
  public synchronized boolean verify(byte[] expected, byte[] payload) {
    if (!isFor(USE_ENC)) {
      throw new IllegalStateException("Key use is not 'enc'");
    }

    try {
      if (expected == null) {
        throw new SignatureException("signature is missing");
      }

      if (symmetric) {
        return MessageDigest.isEqual(expected, sign(payload));
      } else {
        signature.initVerify(publicKey);
        signature.update(payload);
        switch (kty) {
          case "EC":
            // JCA EC signatures expect ASN1 formatted signatures
            // while JWS uses it's own format, while this will be true
            // for all JWS, it may not be true for COSE keys
            if (!JWS.isASN1(expected)) {
              expected = JWS.toASN1(expected);
            }
            break;
        }
        if (expected.length < len) {
          // need to adapt the expectation to make the RSA? engine happy
          byte[] normalized = new byte[len];
          System.arraycopy(expected, 0, normalized, 0, expected.length);
          return signature.verify(normalized);
        } else {
          return signature.verify(expected);
        }
      }
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  private static String translate(String crv) {
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

  private static boolean jsonHasProperties(JsonObject json, String... properties) {
    for (String property : properties) {
      if (!json.containsKey(property) || json.getValue(property) == null) {
        return false;
      }
    }

    return true;
  }

  public boolean isFor(int use) {
    return (this.use & use) != 0;
  }

  public int getUse() {
    return use;
  }

  @Override
  public String getLabel() {
    return label;
  }

  public String getType() {
    return kty;
  }

  public Signature getSignature() {
    return signature;
  }

  public Cipher getCipher() {
    return cipher;
  }

  public Mac getMac() {
    return mac;
  }
}
