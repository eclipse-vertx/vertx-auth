package io.vertx.ext.auth.impl.hash;

import io.vertx.core.VertxException;
import io.vertx.ext.auth.HashingAlgorithm;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PBKDF2 implements HashingAlgorithm {

  private static final int DEFAULT_ITERATIONS = 10000;

  private static final Set<String> DEFAULT_CONFIG = new HashSet<String>() {{
    add("it");
  }};

  private final SecretKeyFactory skf;

  public PBKDF2() {
    try {
      skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("PBKDF2 is not available", nsae);
    }
  }

  @Override
  public String id() {
    return "pbkdf2";
  }

  @Override
  public Set<String> params() {
    return DEFAULT_CONFIG;
  }

  @Override
  public byte[] hash(Map<String, String> params, String password, byte[] salt) {

    int iterations;

    try {
      if (params != null) {
        iterations = Integer.getInteger(params.get("it"));
      } else {
        iterations = DEFAULT_ITERATIONS;
      }
    } catch (RuntimeException e) {
      iterations = DEFAULT_ITERATIONS;
    }

    PBEKeySpec spec = new PBEKeySpec(
      password.toCharArray(),
      salt,
      iterations,
      64 * 8);

    try {
      return skf.generateSecret(spec).getEncoded();
    } catch (InvalidKeySpecException ikse) {
      throw new RuntimeException(ikse);
    }
  }
}
