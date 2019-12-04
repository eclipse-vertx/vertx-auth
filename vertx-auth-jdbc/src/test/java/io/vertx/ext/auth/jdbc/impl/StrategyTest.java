package io.vertx.ext.auth.jdbc.impl;

import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.HashMap;

@RunWith(VertxUnitRunner.class)
public class StrategyTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testStrategy() {
    JDBCHashStrategy strategy = new PBKDF2Strategy(rule.vertx());
    String hashedPassword = strategy.computeHash("Paulo", "123456", -1);
    System.out.println(hashedPassword);

    HashingStrategy common = HashingStrategy.load();
    String commonHash = common.hash("pbkdf2", new HashMap<>(), "123456", "Paulo");
    System.out.println(commonHash);
  }
}
