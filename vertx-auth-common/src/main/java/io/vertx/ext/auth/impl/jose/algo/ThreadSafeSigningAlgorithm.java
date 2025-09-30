package io.vertx.ext.auth.impl.jose.algo;

import java.security.GeneralSecurityException;

public class ThreadSafeSigningAlgorithm extends SigningAlgorithm {

  private final SigningAlgorithm algorithm;

  public ThreadSafeSigningAlgorithm(SigningAlgorithm algorithm) {
    this.algorithm = algorithm;
  }

  @Override
  public SigningAlgorithm safe() {
    return this;
  }

  @Override
  public SigningAlgorithm unwrap() {
    return algorithm.unwrap();
  }

  @Override
  public String name() {
    return algorithm.name();
  }

  @Override
  public String id() {
    return algorithm.id();
  }

  @Override
  public boolean canSign() {
    return algorithm.canSign();
  }

  @Override
  public boolean canVerify() {
    return algorithm.canVerify();
  }

  @Override
  public Signer signer() throws GeneralSecurityException {
    Signer signer = algorithm.signer();
    return payload -> {
      synchronized (signer) {
        return signer.sign(payload);
      }
    };
  }

  @Override
  public Verifier verifier() throws GeneralSecurityException {
    Verifier verifier = algorithm.verifier();
    return (signature, payload) -> {
      synchronized (verifier) {
        return verifier.verify(signature, payload);
      }
    };
  }
}
