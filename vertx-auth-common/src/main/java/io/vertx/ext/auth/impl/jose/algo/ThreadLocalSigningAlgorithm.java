package io.vertx.ext.auth.impl.jose.algo;

import io.netty.util.internal.PlatformDependent;

import java.security.GeneralSecurityException;

public class ThreadLocalSigningAlgorithm extends SigningAlgorithm {

  private final SigningAlgorithm algorithm;
  private final ThreadLocal<Signer> localSigner = new ThreadLocal<>() {
    @Override
    protected Signer initialValue() {
      try {
        return algorithm.signer();
      } catch (GeneralSecurityException e) {
        PlatformDependent.throwException(e);
        return null;
      }
    }
  };
  private final ThreadLocal<Verifier> localVerifier = new ThreadLocal<>() {
    @Override
    protected Verifier initialValue() {
      try {
        return algorithm.verifier();
      } catch (GeneralSecurityException e) {
        PlatformDependent.throwException(e);
        return null;
      }
    }
  };

  public ThreadLocalSigningAlgorithm(SigningAlgorithm algorithm) {
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
    return payload -> localSigner.get().sign(payload);
  }

  @Override
  public Verifier verifier() throws GeneralSecurityException {
    return (signature, payload) -> localVerifier.get().verify(signature, payload);
  }
}
