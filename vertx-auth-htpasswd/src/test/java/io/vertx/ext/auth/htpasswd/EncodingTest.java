package io.vertx.ext.auth.htpasswd;

import io.vertx.ext.auth.HashingStrategy;
import org.junit.Test;

import static org.junit.Assert.*;

public class EncodingTest {

  private final HashingStrategy strategy = HashingStrategy.load();

  @Test
  public void testSHA1() {
    assertTrue(strategy.verify("{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "password"));
    assertFalse(strategy.verify("{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj8g=", "password"));
  }

  @Test
  public void testCrypt() {
    assertTrue(strategy.verify("b5R8K8YXZaSq2", "password"));
    assertFalse(strategy.verify("b5R8K8YXZaSq3", "password"));
  }

  @Test
  public void testBrypt() {
    // this test should fail as there is no known open source project that can generate $2y$ hashes
    assertFalse(strategy.verify("$2y$10$wBza2CzSTNeOjMdrwq.UquoCj4cPpdOzcF0/.JPqLJQ2qQDpT4ehG", "password"));
  }

  @Test
  public void testAPR1() {
    assertTrue(strategy.verify("$apr1$vm2xls13$Rk6E1Pqoep3Ze9fvQMDBU/", "password"));
    assertFalse(strategy.verify("$apr1$vm2xls13$Rk6E1Pqoep3Ze0fvQMDBU/", "password"));
  }
}
