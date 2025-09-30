package io.vertx.ext.auth.impl.jose.algo;

import io.vertx.core.VertxException;
import io.vertx.ext.auth.impl.jose.Algorithm;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public abstract class SigningAlgorithm {

  private static char[] password(String keyStorePassword, Map<String, String> passwordProtection, String alias) {
    String password;
    if (passwordProtection == null || (password = passwordProtection.get(alias)) == null) {
      password = keyStorePassword;
    }
    return password.toCharArray();
  }

  private static boolean invalidAlgAlias(String alg, String alias) {
    try {
      Algorithm algo = Algorithm.valueOf(alias);
      return !alg.equalsIgnoreCase(algo.jce) && !alg.equalsIgnoreCase(algo.oid);
    } catch (IllegalArgumentException e) {
      return true;
    }
  }

  public static SigningAlgorithm create(KeyStore keyStore, String alias, char[] password) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, CertificateNotYetValidException, CertificateExpiredException {
    KeyStore.Entry entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection(password));
    if (entry != null) {
      if (entry instanceof KeyStore.SecretKeyEntry) {
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) entry;
        if (MacSigningAlgorithm.isValidAlgo(secretKeyEntry.getSecretKey().getAlgorithm())) {
          return new MacSigningAlgorithm(secretKeyEntry.getSecretKey());
        }
      } else if (entry instanceof KeyStore.PrivateKeyEntry) {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        // Key pairs on keystores are stored with a certificate, so we use it to load a key pair
        X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
        // not found
        if (certificate == null) {
          return null;
        }
        // start validation
        certificate.checkValidity();
        // verify that the algorithms match
        // the algorithm cannot be null, and it cannot be different from the alias list
        // algorithm is valid
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        PublicKey publicKey = certificate.getPublicKey();
        Callable<Signature> signatureFactory = () -> Signature.getInstance(certificate.getSigAlgName());

        // TODO : test all supported algo from key store
        int len;
        switch (certificate.getSigAlgName()) {
          case "SHA256withRSA":
            len = 256;
            break;
          default:
            throw new NoSuchAlgorithmException(certificate.getSigAlgName());
        }
        return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(alias, privateKey, publicKey, "" + certificate.hashCode(), signatureFactory, len);
      } else {
        throw new UnrecoverableEntryException();
      }
    }
    return null;
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

    // TODO : merge the two for-each blocks

    // load MACs
    for (String alias : Arrays.asList("HS256", "HS384", "HS512")) {
      // algorithm is valid
      try {
        char[] password = password(keyStorePassword, passwordProtection, alias);
        SigningAlgorithm a = create(keyStore, alias, password);
        // key store does not have the requested algorithm
        if (a == null) {
          continue;
        }
        // the algorithm cannot be null, and it cannot be different from the alias list
        if (invalidAlgAlias(a.name(), alias)) {
          keys.add(new Failure("The key algorithm does not match: {" + alias + ": " + a.name() + "}"));
          continue;
        }

        keys.add(new Algo(a));
      } catch (Exception e) {
        keys.add(new Failure(e));
      }
    }

    for (String alias : Arrays.asList("RS256", "RS384", "RS512", "ES256K", "ES256", "ES384", "ES512")) {
      try {
        char[] password = password(keyStorePassword, passwordProtection, alias);
        PubKeySigningAlgorithm a = (PubKeySigningAlgorithm) create(keyStore, alias, password);
        if (a == null) {
          continue;
        }
        if (invalidAlgAlias(a.signature().getAlgorithm(), alias)) {
          keys.add(new Failure("The key algorithm does not match: {" + alias + ": " + a.signature().getAlgorithm() + "}"));
          continue;
        }
        keys.add(new Algo(a));
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
