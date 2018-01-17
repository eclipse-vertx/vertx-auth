package io.vertx.ext.auth.jdbc.impl;

import io.vertx.core.Vertx;
import io.vertx.core.VertxException;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512Strategy extends AbstractHashingStrategy implements JDBCHashStrategy {

  private final MessageDigest md;

  public SHA512Strategy(Vertx vertx) {
    super(vertx);

    try {
      md = MessageDigest.getInstance("SHA-512");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("SHA-512 is not available", nsae);
    }
  }

  @Override
  public String computeHash(String password, String salt, int version) {

    String concat =
      (salt == null ? "" : salt) +
        password;

    if (version >= 0) {
      if (nonces == null) {
        // the nonce version is not a number
        throw new VertxException("nonces are not available");
      }
      if (version < nonces.size()) {
        concat += nonces.getString(version);
      }
    }

    byte[] bHash = md.digest(concat.getBytes(StandardCharsets.UTF_8));
    if (version >= 0) {
      return bytesToHex(bHash) + '$' + version;
    } else {
      return bytesToHex(bHash);
    }
  }
}
