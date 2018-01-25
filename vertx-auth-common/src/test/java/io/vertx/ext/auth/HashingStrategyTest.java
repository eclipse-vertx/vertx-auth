package io.vertx.ext.auth;

import org.junit.Test;

import static org.junit.Assert.*;

public class HashingStrategyTest {

  @Test
  public void testHashSimple() {
    HashingStrategy strategy = HashingStrategy.load();
    // should encode
    String hash = strategy.hash("sha512", null, "keyboard.cat".getBytes(), "SuperSecret$!");
    // should be valid
    assertTrue(strategy.verify(hash, "SuperSecret$!"));
    // should be wrong
    assertFalse(strategy.verify(hash, "superSecret$!"));
  }

  @Test
  public void testHashStronger() {
    HashingStrategy strategy = HashingStrategy.load();
    // should encode
    String hash = strategy.hash("pbkdf2", null, "keyboard.cat".getBytes(), "SuperSecret$!");
    // should be valid
    assertTrue(strategy.verify(hash, "SuperSecret$!"));
    // should be wrong
    assertFalse(strategy.verify(hash, "superSecret$!"));
  }
}
