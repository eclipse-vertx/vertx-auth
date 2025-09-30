package io.vertx.ext.auth.impl.jose.algo;

import java.security.GeneralSecurityException;

/**
 * Token signing contract.
 */
@FunctionalInterface
public interface Signer {

  /**
   * Sign the payload.
   *
   * @param payload
   * @return
   * @throws GeneralSecurityException
   */
  byte[] sign(byte[] payload) throws GeneralSecurityException;

}
