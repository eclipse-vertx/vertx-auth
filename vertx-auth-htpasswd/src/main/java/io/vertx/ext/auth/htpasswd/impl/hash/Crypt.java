package io.vertx.ext.auth.htpasswd.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;

import org.apache.commons.codec.digest.UnixCrypt;

public class Crypt implements HashingAlgorithm {

  @Override
  public String id() {
    return "";
  }

  @Override
  public String hash(HashString hashString, String password) {
    // htpasswd uses the first 2 bytes as salt
    final String cryptSalt = hashString.hash().substring(0, 2);
    return UnixCrypt.crypt(password, cryptSalt);
  }
}
