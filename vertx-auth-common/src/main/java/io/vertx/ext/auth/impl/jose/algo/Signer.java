package io.vertx.ext.auth.impl.jose.algo;

import java.security.GeneralSecurityException;

public interface Signer {
  byte[] sign(byte[] data) throws GeneralSecurityException;
  boolean verify(byte[] expected, byte[] payload) throws GeneralSecurityException;
}
