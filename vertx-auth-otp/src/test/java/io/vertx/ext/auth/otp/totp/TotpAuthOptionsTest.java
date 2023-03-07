package io.vertx.ext.auth.otp.totp;

import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class TotpAuthOptionsTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void test1(TestContext should) {
    try {
      new TotpAuthOptions()
        .setPasswordLength(0);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(5);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(6);
    } catch (IllegalArgumentException e) {
      should.fail();
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(7);
    } catch (IllegalArgumentException e) {
      should.fail();
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(8);
    } catch (IllegalArgumentException e) {
      should.fail();
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(9);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(10);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(Integer.MAX_VALUE);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      new TotpAuthOptions()
        .setPasswordLength(Integer.MIN_VALUE);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      new TotpAuthOptions()
        .setAuthAttemptsLimit(-1);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      new TotpAuthOptions()
        .setAuthAttemptsLimit(Integer.MIN_VALUE);
      should.fail();
    } catch (IllegalArgumentException ignore) {
    }

    try {
      final TotpAuthOptions hotpAuthOptions = new TotpAuthOptions()
        .setAuthAttemptsLimit(5);
      should.assertTrue(hotpAuthOptions.isUsingAttemptsLimit());
    } catch (IllegalArgumentException ignore) {
    }

    try {
      final TotpAuthOptions hotpAuthOptions = new TotpAuthOptions()
        .setAuthAttemptsLimit(0);
      should.assertFalse(hotpAuthOptions.isUsingAttemptsLimit());
    } catch (IllegalArgumentException ignore) {
    }
  }
}
