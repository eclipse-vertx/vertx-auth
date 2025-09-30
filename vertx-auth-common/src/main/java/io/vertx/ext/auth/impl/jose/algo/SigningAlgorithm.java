package io.vertx.ext.auth.impl.jose.algo;

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
import java.util.concurrent.Callable;

/**
 * Signing algorithm for tokens.
 */
public abstract class SigningAlgorithm {

  /**
   * Create a {@link SigningAlgorithm} from a keystore entry.
   *
   * @param entry the keystore entry, it must be a {@link KeyStore.SecretKeyEntry} or a {@link KeyStore.PrivateKeyEntry}
   * @return the signing algorithm instance
   */
  public static SigningAlgorithm create(KeyStore.Entry entry) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, CertificateNotYetValidException, CertificateExpiredException {
    if (entry instanceof KeyStore.SecretKeyEntry) {
      KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) entry;
      return new MacSignaingAlgorithm(secretKeyEntry.getSecretKey());
    } else if (entry instanceof KeyStore.PrivateKeyEntry) {
      KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
      // Key pairs on keystores are stored with a certificate, so we use it to load a key pair
      X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
      // start validation
      certificate.checkValidity();
      // verify that the algorithms match
      // the algorithm cannot be null, and it cannot be different from the alias list
      // algorithm is valid
      PrivateKey privateKey = privateKeyEntry.getPrivateKey();
      PublicKey publicKey = certificate.getPublicKey();
      Callable<Signature> signatureFactory = () -> Signature.getInstance(certificate.getSigAlgName());
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
      return DigitalSigningAlgorithm.createPubKeySigningAlgorithm(certificate.getSigAlgName(), privateKey, publicKey, "" + certificate.hashCode(), signatureFactory, len);
    } else {
      throw new UnsupportedOperationException();
    }
  }

  /**
   * @return a thread safe version of this instance
   */
  public SigningAlgorithm safe() {
    // Make this configurable through system properties ???
//    return new ThreadSafeSigningAlgorithm(this);
    return new ThreadLocalSigningAlgorithm(this);
  }

  /**
   * @return the original instance that must be an instance of {@link DigitalSigningAlgorithm} or {@link MacSignaingAlgorithm}
   */
  public SigningAlgorithm unwrap() {
    return this;
  }

  public abstract String name();

  public abstract String id();

  public abstract boolean canSign();

  public abstract boolean canVerify();

  public abstract Signer signer() throws GeneralSecurityException;

  public abstract Verifier verifier() throws GeneralSecurityException;

}
