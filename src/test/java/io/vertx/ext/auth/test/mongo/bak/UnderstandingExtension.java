package io.vertx.ext.auth.test.mongo.bak;

import org.junit.AfterClass;
import org.junit.BeforeClass;

public class UnderstandingExtension extends UnderstandingTestCasesVertx {

  @BeforeClass
  public static void beforeClass() {
    System.out.println("beforeClass extended");
  }

  @AfterClass
  public static void afterClass() {
    System.out.println("afterClass extended");
  }

  public UnderstandingExtension() {
  }

}
