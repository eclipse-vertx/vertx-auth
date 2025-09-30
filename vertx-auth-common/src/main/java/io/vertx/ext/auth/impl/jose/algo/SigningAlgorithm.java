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
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public abstract class SigningAlgorithm {

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
        if (publicKey instanceof RSAKey) {
          len = ((RSAKey) publicKey).getModulus().bitLength() + 7 >> 3;
        } else {
          switch (certificate.getSigAlgName()) {
            case "SHA256withECDSA":
              len = 64;
              break;
            case "SHA384withECDSA":
              len = 96;
              break;
            case "SHA512withECDSA":
              len = 132;
              break;
            default:
              throw new NoSuchAlgorithmException(certificate.getSigAlgName());
          }
        }
        return PubKeySigningAlgorithm.createPubKeySigningAlgorithm(certificate.getSigAlgName(), privateKey, publicKey, "" + certificate.hashCode(), signatureFactory, len);
      } else {
        throw new UnrecoverableEntryException();
      }
    }
    return null;
  }

  public abstract String name();

  public abstract String id();

  public abstract boolean canSign();

  public abstract boolean canVerify();

  public abstract Signer signer() throws GeneralSecurityException;

}
