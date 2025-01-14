package io.vertx.tests.authorization.impl;

import io.vertx.core.MultiMap;
import io.vertx.ext.auth.authorization.impl.VariableAwareExpression;
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

  @Test
  public void test2() {
    VariableAwareExpression expression = new VariableAwareExpression("{bar}end");
    String resolved = expression.resolve(MultiMap.caseInsensitiveMultiMap().add("bar", "foo"));
    assertEquals("fooend", resolved);
  }

  @Test
  public void test3() {
    VariableAwareExpression expression = new VariableAwareExpression("begin{bar}");
    String resolved = expression.resolve(MultiMap.caseInsensitiveMultiMap().add("bar", "foo"));
    assertEquals("beginfoo", resolved);
  }

  @Test
  public void test4() {
    VariableAwareExpression expression = new VariableAwareExpression("part1,part2{bar}");
    String resolved = expression.resolve(MultiMap.caseInsensitiveMultiMap().add("bar", "foo"));
    assertEquals("part1,part2foo", resolved);
  }

  @Test
  public void test5() {
    VariableAwareExpression expression = new VariableAwareExpression("part1{bar}part2,part3");
    String resolved = expression.resolve(MultiMap.caseInsensitiveMultiMap().add("bar", "foo"));
    assertEquals("part1foopart2,part3", resolved);
  }
}
