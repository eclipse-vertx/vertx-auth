package io.vertx.ext.auth.jdbc.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import static org.junit.Assert.*;

public class PBKDF2StrategyTest extends VertxTestBase {

  @Test
  public void createHashTest() {
    JDBCHashStrategy strategy = new PBKDF2Strategy(vertx);

    String hashedPassword = strategy.computeHash("Paulo", "123456", -1);
    assertTrue(JDBCHashStrategy.isEqual("909EB69A26BAF1ED273FE5D7A7673A56747A26C9FB7DFFE9A5EDA8275EAC5548B9FCB1E9FFF454834205414DF4D6A419E68A764472C910709A1F9C11759C1E16", hashedPassword));
  }

  @Test
  public void createHashTestWithVersion() {
    JDBCHashStrategy strategy = new PBKDF2Strategy(vertx);
    strategy.setNonces(new JsonArray().add(1000));

    String hashedPassword = strategy.computeHash("Paulo", "123456", 0);
    assertTrue(JDBCHashStrategy.isEqual("5873E323FD8E5797177A13C474BF618474243DF0C77D6C042ED4539ADE6536BDC09C80AB17F2818B83B50518E788164DAEEE75A0017E8359D7101CE50A2DCE51$0", hashedPassword));
  }

  @Test
  public void createHashAppleStyleTest() {
    JDBCHashStrategy strategy = new PBKDF2Strategy(vertx);
    strategy.setNonces(new JsonArray().add(1).add(10000));

    String hashedPassword = strategy.computeHash("Paulo", "123456", 1);
    assertTrue(JDBCHashStrategy.isEqual("909EB69A26BAF1ED273FE5D7A7673A56747A26C9FB7DFFE9A5EDA8275EAC5548B9FCB1E9FFF454834205414DF4D6A419E68A764472C910709A1F9C11759C1E16$1", hashedPassword));
  }
}
