package io.vertx.ext.auth.impl.jose.algo;

import java.security.GeneralSecurityException;

/**
 * Token signature verification contract.
 */
@FunctionalInterface
public interface Verifier {

  /**
   * Verify {@code payload} matches the {@code signature}.
   *
   * @param signature the expected result
   * @param payload the tested data
   * @return whether verification succeeded
   * @throws GeneralSecurityException anything that could prevent verification to happen
   */
  boolean verify(byte[] signature, byte[] payload) throws GeneralSecurityException;
}
