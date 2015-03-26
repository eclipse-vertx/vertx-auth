package io.vertx.ext.auth.test.mongo;

import io.vertx.ext.unit.TestCompletion;
import io.vertx.ext.unit.TestOptions;
import io.vertx.ext.unit.TestSuite;
import io.vertx.ext.unit.report.ReportOptions;

/**
 * @author mremme
 */

public class MongoAuthTest {
  MongoTestBase mongoTestBase = new MongoTestBase();

  /**
   * 
   */
  public MongoAuthTest() {
  }

  private void test() {
    TestSuite suite = TestSuite.create("the_test_suite");

    suite.before(mongoTestBase.getBeforeHandler());
    suite.after(mongoTestBase.getAfterHandler());

    TestOptions options = new TestOptions().addReporter(new ReportOptions().setTo("console").setFormat("simple"))
        .setTimeout(5000);

    TestCompletion completion = suite.run(mongoTestBase.vertx, options);

    // Simple completion callback
    completion.await();
    completion.handler(ar -> {
      if (ar.succeeded()) {
        System.out.println("Test suite passed!");
      } else {
        System.out.println("Test suite failed:");
        ar.cause().printStackTrace();
      }
    });
    System.exit(0);
  }

  public static void main(String[] args) {
    MongoAuthTest authTest = new MongoAuthTest();
    authTest.test();
  }

}
