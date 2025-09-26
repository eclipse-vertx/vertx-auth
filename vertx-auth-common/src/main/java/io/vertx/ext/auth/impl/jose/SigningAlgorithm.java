package io.vertx.ext.auth.impl.jose;

import java.security.GeneralSecurityException;

public interface SigningAlgorithm {

  String name();

  boolean canSign();

  boolean canVerify();

  Signer signer() throws GeneralSecurityException;

}
