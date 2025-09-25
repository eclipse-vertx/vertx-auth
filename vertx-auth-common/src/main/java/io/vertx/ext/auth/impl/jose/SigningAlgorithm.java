package io.vertx.ext.auth.impl.jose;

import java.security.GeneralSecurityException;

public interface SigningAlgorithm {

  String name();

  Signer signer() throws GeneralSecurityException;

}
