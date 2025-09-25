package io.vertx.ext.auth.impl.jose;

import java.security.GeneralSecurityException;

public interface SigningAlgorithm {

  Signer signer() throws GeneralSecurityException;

}
