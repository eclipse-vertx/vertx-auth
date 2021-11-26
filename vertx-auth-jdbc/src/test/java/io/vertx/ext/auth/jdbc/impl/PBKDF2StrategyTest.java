package io.vertx.ext.auth.jdbc.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertTrue;

@RunWith(VertxUnitRunner.class)
public class PBKDF2StrategyTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void createHashTest() {
    JDBCHashStrategy strategy = new PBKDF2Strategy(rule.vertx());

    String hashedPassword = strategy.computeHash("Paulo", "123456", -1);
    assertTrue(JDBCHashStrategy.isEqual("3EF08FDF601E24F9D9DF99F2A199A563E1EB4C8C467D61962B9526001EF6FA9F31C2F89FCA7690CF022E11AF89DA8BFD4D18E8A0FC888A745C8DD7AAB92A359B", hashedPassword));
  }

  @Test
  public void createHashTestWithVersion() {
    JDBCHashStrategy strategy = new PBKDF2Strategy(rule.vertx());
    strategy.setNonces(new JsonArray().add(1000));

    String hashedPassword = strategy.computeHash("Paulo", "123456", 0);
    assertTrue(JDBCHashStrategy.isEqual("39698770CC0B0B0553E9B74216FAE2C7C31B81D40940FA50601D7998B81820F86CEE7CD84CC1D06D06D832C5BACA45D3215F6B0F3F484931AE846915449BF72F$0", hashedPassword));
  }

  @Test
  public void createHashAppleStyleTest() {
    JDBCHashStrategy strategy = new PBKDF2Strategy(rule.vertx());
    strategy.setNonces(new JsonArray().add(1).add(10000));

    String hashedPassword = strategy.computeHash("Paulo", "123456", 1);
    assertTrue(JDBCHashStrategy.isEqual("3EF08FDF601E24F9D9DF99F2A199A563E1EB4C8C467D61962B9526001EF6FA9F31C2F89FCA7690CF022E11AF89DA8BFD4D18E8A0FC888A745C8DD7AAB92A359B$1", hashedPassword));
  }
}
