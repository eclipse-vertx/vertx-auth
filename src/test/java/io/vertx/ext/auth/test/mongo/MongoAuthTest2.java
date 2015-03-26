/**
 * 
 */
package io.vertx.ext.auth.test.mongo;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.unit.TestCompletion;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.TestOptions;
import io.vertx.ext.unit.TestSuite;
import io.vertx.ext.unit.report.ReportOptions;

/**
 * @author mremme
 */
public class MongoAuthTest2 {

  public static void Test() {
    Vertx vertx = Vertx.vertx();
    TestSuite suite = TestSuite.create("the_test_suite");

    suite.beforeEach(new BeforeEachHandler());
    suite.afterEach(new AfterEachHandler());
    suite.before(new BeforeHandler());
    suite.after(new AfterHandler());

    suite.test("my_test_case", context -> {
      String s = "value";
      context.assertEquals("value", s);
    }).test("my_test_case2", context -> {
      String s = "value";
      context.assertEquals("value", s);
    });

    TestOptions options = new TestOptions().addReporter(new ReportOptions().setTo("console").setFormat("simple"))
        .setTimeout(5000);

    TestCompletion completion = suite.run(vertx, options);

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
    Test();
  }

}

class BeforeEachHandler implements Handler<TestContext> {

  /*
   * (non-Javadoc)
   * @see io.vertx.core.Handler#handle(java.lang.Object)
   */
  @Override
  public void handle(TestContext context) {
    System.out.println(getClass().getSimpleName());
  }

}

class AfterEachHandler implements Handler<TestContext> {

  /*
   * (non-Javadoc)
   * @see io.vertx.core.Handler#handle(java.lang.Object)
   */
  @Override
  public void handle(TestContext context) {
    System.out.println(getClass().getSimpleName());
  }

}

class BeforeHandler implements Handler<TestContext> {

  /*
   * (non-Javadoc)
   * @see io.vertx.core.Handler#handle(java.lang.Object)
   */
  @Override
  public void handle(TestContext context) {
    System.out.println(getClass().getSimpleName());
  }

}

class AfterHandler implements Handler<TestContext> {

  /*
   * (non-Javadoc)
   * @see io.vertx.core.Handler#handle(java.lang.Object)
   */
  @Override
  public void handle(TestContext context) {
    System.out.println(getClass().getSimpleName());
  }

}
