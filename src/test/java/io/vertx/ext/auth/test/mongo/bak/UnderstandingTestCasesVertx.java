package io.vertx.ext.auth.test.mongo.bak;

import io.vertx.test.core.VertxTestBase;

import java.util.concurrent.CountDownLatch;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * <br>
 * <br>
 * Copyright: Copyright (c) 27.03.2015 <br>
 * Company: Braintags GmbH <br>
 * 
 * @author mremme
 */

public class UnderstandingTestCasesVertx extends VertxTestBase {

  /**
   * 
   */
  public UnderstandingTestCasesVertx() {
  }

  @BeforeClass
  public static void beforeClass() {
    System.out.println("beforeClass");
  }

  @AfterClass
  public static void afterClass() {
    System.out.println("afterClass");
  }

  /*
   * (non-Javadoc)
   * @see io.vertx.test.core.VertxTestBase#setUp()
   */
  @Override
  public void setUp() throws Exception {
    super.setUp();
    System.out.println("setUp");
  }

  /*
   * (non-Javadoc)
   * @see io.vertx.test.core.VertxTestBase#tearDown()
   */
  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
    System.out.println("tearDown");
  }

  @Test
  public void performTest1() {
    System.out.println("performTest1");
  }

  @Test
  public void performTest2() {
    System.out.println("performTest2");
  }

  @Test
  public void performTest3() {
    System.out.println("performTest3");
  }

  /**
   * Ohne die Anwendung von Latch würde der Loop nicht fertig ausgeführt, weil die anderen Tests vorher fertig sind und
   * die Sequenz beendet wird. Mit dem Latch wird auf die Abarbeitung derSequenz gewartet und dann erst werden die
   * anderen Tests ausgeführt
   */
  @Test
  public void performThreadTest() {
    System.out.println("performThreadTest");
    int loop = 100;
    CountDownLatch latch = new CountDownLatch(loop);
    Thread thread = new Thread(new Runnable() {

      @Override
      public void run() {
        for (int i = 0; i < loop; i++) {
          System.out.println("loop / latch: " + i + " / " + latch.getCount());
          try {
            Thread.sleep(20);
          } catch (InterruptedException e) {
            e.printStackTrace();
          }
          latch.countDown();
        }

      }
    });
    thread.start();

    try {
      latch.await();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  /**
   * Ähnlich, allerdings ohne vorgegebenen Counter.
   */
  @Test
  public void performThreadTest2() {
    System.out.println("performThreadTest2");
    int loop = 100;
    Thread thread = new Thread(new Runnable() {

      @Override
      public void run() {
        for (int i = 0; i < loop; i++) {
          System.out.println("zweiter: loop / latch: " + i + " / ");
          try {
            Thread.sleep(20);
          } catch (InterruptedException e) {
            e.printStackTrace();
          }
        }
        testComplete();
      }
    });
    thread.start();

    await();
  }

}
