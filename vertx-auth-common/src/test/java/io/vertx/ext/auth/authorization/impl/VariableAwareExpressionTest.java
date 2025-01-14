package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.MultiMap;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import org.junit.Test;

import java.util.function.Function;

import static org.junit.Assert.assertEquals;

public class VariableAwareExpressionTest {

  @Test
  public void test2() {
    VariableAwareExpression expression = new VariableAwareExpression("{bar}end");
    String resolved = expression.resolve(new MockAuthorizationContext(MultiMap.caseInsensitiveMultiMap().add("bar", "foo")));
    Function<AuthorizationContext, String>[] parts = expression.parts();
    assertEquals("fooend", resolved);
  }

  @Test
  public void test3() {
    VariableAwareExpression expression = new VariableAwareExpression("begin{bar}");
    String resolved = expression.resolve(new MockAuthorizationContext(MultiMap.caseInsensitiveMultiMap().add("bar", "foo")));
    assertEquals("beginfoo", resolved);
  }

  @Test
  public void test4() {
    VariableAwareExpression expression = new VariableAwareExpression("part1,part2{bar}");
    String resolved = expression.resolve(new MockAuthorizationContext(MultiMap.caseInsensitiveMultiMap().add("bar", "foo")));
    assertEquals("part1,part2foo", resolved);
  }

  @Test
  public void test5() {
    VariableAwareExpression expression = new VariableAwareExpression("part1{bar}part2,part3");
    String resolved = expression.resolve(new MockAuthorizationContext(MultiMap.caseInsensitiveMultiMap().add("bar", "foo")));
    assertEquals("part1foopart2,part3", resolved);
  }

  private static class MockAuthorizationContext implements AuthorizationContext {

    private final MultiMap variables;

    public MockAuthorizationContext(MultiMap variables) {
      this.variables = variables;
    }

    @Override
    public User user() {
      return null;
    }

    @Override
    public MultiMap variables() {
      return variables;
    }
  }
}
