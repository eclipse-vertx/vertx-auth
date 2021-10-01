package io.vertx.ext.auth.jdbc.impl;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;

import static io.vertx.ext.auth.impl.Codec.base16Encode;

@Deprecated
public abstract class AbstractHashingStrategy implements JDBCHashStrategy {

  private final PRNG random;
  protected JsonArray nonces;

  AbstractHashingStrategy(Vertx vertx) {
    random = new PRNG(vertx);
  }

  @Override
  public String generateSalt() {
    byte[] salt = new byte[32];
    random.nextBytes(salt);

    return base16Encode(salt).toUpperCase();
  }

  @Override
  public String getHashedStoredPwd(JsonArray row) {
    return row.getString(0);
  }

  @Override
  public String getSalt(JsonArray row) {
    return row.getString(1);
  }

  @Override
  public void setNonces(JsonArray nonces) {
    this.nonces = nonces;
  }
}
