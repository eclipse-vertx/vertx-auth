package io.vertx.ext.auth.htpasswd.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1 implements HashingAlgorithm {

  private final MessageDigest md;

  public SHA1() {
    try {
      md = MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("SHA1 is not available", nsae);
    }
  }

  @Override
  public String id() {
    return "{SHA}";
  }

  @Override
  public String hash(HashString hashString, String password) {
    return B64ENC.encodeToString(md.digest(password.getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public boolean needsSeparator() {
    return false;
  }
}
