package io.vertx.ext.auth;

import org.junit.Test;

import java.util.Base64;

import static org.junit.Assert.*;

public class HashingStrategyTest {

  Base64.Encoder B64ENC = Base64.getEncoder();

  String salt = B64ENC.encodeToString("keyboard.cat".getBytes());

  @Test
  public void testHashSimple() {
    HashingStrategy strategy = HashingStrategy.load();
    // should encode
    String hash = strategy.hash("sha512", null, salt, "SuperSecret$!");
    // should be valid
    assertTrue(strategy.verify(hash, "SuperSecret$!"));
    // should be wrong
    assertFalse(strategy.verify(hash, "superSecret$!"));
  }

  @Test
  public void testHashStronger() {
    HashingStrategy strategy = HashingStrategy.load();
    // should encode
    String hash = strategy.hash("pbkdf2", null, salt, "SuperSecret$!");
    // should be valid
    assertTrue(strategy.verify(hash, "SuperSecret$!"));
    // should be wrong
    assertFalse(strategy.verify(hash, "superSecret$!"));
  }
}
