package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.MultiMap;
import org.junit.Test;

import static org.junit.Assert.*;

public class VariableAwareExpressionTest {

  @Test
  public void test() {
    VariableAwareExpression expression = new VariableAwareExpression("foo");
    String resolved = expression.resolve(MultiMap.caseInsensitiveMultiMap().add("foo", "bar"));
    assertEquals("foo", resolved);
  }

  @Test
  public void test1() {
    VariableAwareExpression expression = new VariableAwareExpression("{foo}");
    String resolved = expression.resolve(MultiMap.caseInsensitiveMultiMap().add("foo", "bar"));
    assertEquals("bar", resolved);
  }
}
