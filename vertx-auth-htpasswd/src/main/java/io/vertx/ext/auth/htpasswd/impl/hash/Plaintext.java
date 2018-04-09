package io.vertx.ext.auth.htpasswd.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;

public class Plaintext implements HashingAlgorithm {

  @Override
  public String id() {
    return "";
  }

  @Override
  public String hash(HashString hashString, String password) {
    return password;
  }
}
