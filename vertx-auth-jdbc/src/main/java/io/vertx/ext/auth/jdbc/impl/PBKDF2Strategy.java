package io.vertx.ext.auth.jdbc.impl;

import io.vertx.core.Vertx;
import io.vertx.core.VertxException;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBKDF2Strategy extends AbstractHashingStrategy implements JDBCHashStrategy {

  private static final int DEFAULT_ITERATIONS = 10000;
  private final SecretKeyFactory skf;

  public PBKDF2Strategy(Vertx vertx) {
    super(vertx);

    try {
      skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("PBKDF2 is not available", nsae);
    }
  }

  @Override
  public String computeHash(String password, String salt, int version) {

    int iterations = DEFAULT_ITERATIONS;

    if (version >= 0) {
      if (nonces == null) {
        // the nonce version is not available
        throw new VertxException("nonces are not available");
      }

      if (version < nonces.size()) {
        iterations = nonces.getInteger(version);
      }
    }

    PBEKeySpec spec = new PBEKeySpec(
      password.toCharArray(),
      salt.getBytes(StandardCharsets.UTF_8),
      iterations,
      64 * 8);

    try {
      byte[] hash = skf.generateSecret(spec).getEncoded();

      if (version >= 0) {
        return bytesToHex(hash) + '$' + version;
      } else {
        return bytesToHex(hash);
      }

    } catch (InvalidKeySpecException ikse) {
      throw new VertxException(ikse);
    }
  }
}
