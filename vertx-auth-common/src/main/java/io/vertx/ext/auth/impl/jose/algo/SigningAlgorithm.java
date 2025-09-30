package io.vertx.ext.auth.impl.jose.algo;

import io.vertx.core.VertxException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public abstract class SigningAlgorithm {

  static final Map<String, List<String>> ALG_ALIAS = Map.of(
          "HS256", Arrays.asList(
                  // JCE
                  "HMacSHA256",
                  // OID
                  "1.2.840.113549.2.9"),
          "HS384", Arrays.asList(
                  // JCE
                  "HMacSHA384",
                  // OID
                  "1.2.840.113549.2.10"),
          "HS512", Arrays.asList(
                  // JCE
                  "HMacSHA512",
                  // OID
                  "1.2.840.113549.2.11"),
          "RS256", Arrays.asList(
                  // JCE
                  "SHA256withRSA",
                  // OID
                  "1.2.840.113549.1.1.11"),
          "RS384", Arrays.asList(
                  // JCE
                  "SHA384withRSA",
                  // OID
                  "1.2.840.113549.1.1.12"),
          "RS512", Arrays.asList(
                  // JCE
                  "SHA512withRSA",
                  // OID
                  "1.2.840.113549.1.1.13"),
          "ES256K", Collections.singletonList("SHA256withECDSA"),
          "ES256", Arrays.asList(
                  // JCE
                  "SHA256withECDSA",
                  // OID
                  "1.2.840.10045.4.3.2"),
          "ES384", Arrays.asList(
                  // JCE
                  "SHA384withECDSA",
                  // OID
                  "1.2.840.10045.4.3.3"),
          "ES512", Arrays.asList(
                  // JCE
                  "SHA512withECDSA",
                  // OID
                  "1.2.840.10045.4.3.4")
  );

  private static char[] password(String keyStorePassword, Map<String, String> passwordProtection, String alias) {
    String password;
    if (passwordProtection == null || (password = passwordProtection.get(alias)) == null) {
      password = keyStorePassword;
    }
    return password.toCharArray();
  }

  private static boolean invalidAlgAlias(String alg, String alias) {
    for (String expected : ALG_ALIAS.get(alias)) {
      if (alg.equalsIgnoreCase(expected)) {
        return false;
      }
    }
    return true;
  }

  public static List<Callable<SigningAlgorithm>> create(KeyStore keyStore, String keyStorePassword, Map<String, String> passwordProtection) {

    class Failure implements Callable<SigningAlgorithm> {
      final Exception exception;
      Failure(String msg) {
        this.exception = VertxException.noStackTrace(msg);
      }
      Failure(Exception exception) {
        this.exception = exception;
      }
      @Override
      public SigningAlgorithm call() throws Exception {
        throw exception;
      }
    }

    class Algo implements Callable<SigningAlgorithm> {
      final SigningAlgorithm algo;
      Algo(SigningAlgorithm algo) {
        this.algo = algo;
      }
      @Override
      public SigningAlgorithm call() throws Exception {
        return algo;
      }
    }

    List<Callable<SigningAlgorithm>> keys = new ArrayList<>();

    // load MACs
    for (String alias : Arrays.asList("HS256", "HS384", "HS512")) {
      // algorithm is valid
      try {
        char[] password = password(keyStorePassword, passwordProtection, alias);
        SecretKey secretKey = (SecretKey) keyStore.getKey(alias, password);

        // key store does not have the requested algorithm
        if (secretKey == null) {
          continue;
        }

        // test the algorithm
        String alg = secretKey.getAlgorithm();
        // the algorithm cannot be null, and it cannot be different from the alias list
        if (invalidAlgAlias(alg, alias)) {
          keys.add(new Failure("The key algorithm does not match: {" + alias + ": " + alg + "}"));
          continue;
        }

        keys.add(new Algo(new MacSigningAlgorithm(alias, secretKey)));
      } catch (Exception e) {
        keys.add(new Failure(e));
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
        // the algorithm cannot be null, and it cannot be different from the alias list
        if (invalidAlgAlias(alg, alias)) {
          keys.add(new Failure("The key algorithm does not match: {" + alias + ": " + alg + "}"));
          continue;
        }
        // algorithm is valid
        char[] password = password(keyStorePassword, passwordProtection, alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        PublicKey publicKey = certificate.getPublicKey();
        PubKeySigningAlgorithm algo = PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alias, privateKey, publicKey, "" + certificate.hashCode());
        keys.add(new Algo(algo));
      } catch (Exception e) {
        keys.add(new Failure(e));
      }
    }

    return keys;
  }

  public abstract String name();

  public abstract String id();

  public abstract boolean canSign();

  public abstract boolean canVerify();

  public abstract Signer signer() throws GeneralSecurityException;

}
