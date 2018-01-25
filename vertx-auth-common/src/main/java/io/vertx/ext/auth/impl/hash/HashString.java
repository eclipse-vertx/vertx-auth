package io.vertx.ext.auth.impl.hash;

import io.vertx.ext.auth.HashingAlgorithm;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class HashString {

  private static final Base64.Decoder B64DEC = Base64.getDecoder();
  private static final Base64.Encoder B64ENC = Base64.getEncoder();

  private String id;
  private Map<String, String> params;
  private String salt;
  private String hash;

  public HashString(String encoded) {
    if (encoded.charAt(0) != '$') {
      throw new RuntimeException("Invalid hash format.");
    }

    String[] parts = encoded.split("\\$");

    switch (parts.length) {
      case 2:
        id = parts[1];
      case 3:
        id = parts[1];
        hash = parts[2];
        break;
      case 4:
        id = parts[1];
        salt = parts[2];
        hash = parts[3];
        break;
      case 5:
        id = parts[1];
        params = new HashMap<>();
        for (String kv : parts[2].split(",")) {
          int eq = kv.indexOf('=');
          if (eq > 0) {
            params.put(kv.substring(0, eq), kv.substring(eq + 1));
          }
        }
        salt = parts[3];
        hash = parts[4];
        break;
    }
  }

  public String id() {
    return id;
  }

  public String param(String param) {
    if (params == null) {
      return null;
    }

    return params.get(param);
  }

  public Map<String, String> params() {
    return params;
  }

  public byte[] salt() {
    if (salt != null) {
      return B64DEC.decode(salt);
    }
    return null;
  }

  public byte[] hash() {
    if (hash != null) {
      return B64DEC.decode(hash);
    }
    return null;
  }

  public static String encode(HashingAlgorithm algorithm, Map<String, String> params, byte[] salt, byte[] hash) {
    StringBuilder sb = new StringBuilder();

    sb.append('$');
    sb.append(algorithm.id());

    if (params != null) {
      sb.append('$');
      boolean notEmpty = false;
      for (String key : algorithm.params()) {
        String value = params.get(key);
        if (value != null) {
          if (notEmpty) {
            sb.append(',');
          }
          sb.append(key);
          sb.append('=');
          sb.append(params.get(key));
          notEmpty = true;
        }
      }
    }
    if (salt != null) {
      sb.append('$');
      sb.append(B64ENC.encodeToString(salt));
    }
    if (hash != null) {
      sb.append('$');
      sb.append(B64ENC.encodeToString(hash));
    }

    return sb.toString();
  }

  @Override
  public String toString() {
    return "id=" + id() + ",params=" + params() + ",salt=" + salt() + ",hash="+hash();
  }
}
