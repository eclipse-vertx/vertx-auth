package io.vertx.ext.auth.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
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
  public String hash(HashString hashString, String password) {

    int iterations;

    try {
      if (hashString.params() != null) {
        iterations = Integer.getInteger(hashString.params().get("it"));
      } else {
        iterations = DEFAULT_ITERATIONS;
      }
    } catch (RuntimeException e) {
      iterations = DEFAULT_ITERATIONS;
    }

    if (hashString.salt() == null) {
      throw new RuntimeException("hashString salt is null");
    }

    byte[] salt = B64DEC.decode(hashString.salt());

    PBEKeySpec spec = new PBEKeySpec(
      password.toCharArray(),
      salt,
      iterations,
      64 * 8);

    try {
      return B64ENC.encodeToString(skf.generateSecret(spec).getEncoded());
    } catch (InvalidKeySpecException ikse) {
      throw new RuntimeException(ikse);
    }
  }
}
