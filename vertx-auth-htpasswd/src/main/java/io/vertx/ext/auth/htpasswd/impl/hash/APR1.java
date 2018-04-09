package io.vertx.ext.auth.htpasswd.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;
import org.apache.commons.codec.digest.Md5Crypt;

public class APR1 implements HashingAlgorithm {

  @Override
  public String id() {
    return "apr1";
  }

  @Override
  public String hash(HashString hashString, String password) {
    final String apr1Salt = "$apr1$" + hashString.salt();
    String res = Md5Crypt.apr1Crypt(password, apr1Salt);
    // we need to exclude the salt part
    return res.substring(apr1Salt.length() + 1);
  }
}
