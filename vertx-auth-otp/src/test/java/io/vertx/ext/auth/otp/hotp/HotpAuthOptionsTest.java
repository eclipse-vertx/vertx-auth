/*
 * Copyright (c) 2021 Dmitry Novikov
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.ext.auth.otp.hotp;

import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class HotpAuthOptionsTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void test1(TestContext should) {
    try {
      new HotpAuthOptions()
        .setPasswordLength(0);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(5);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(6);
    } catch (IllegalArgumentException e) {
      should.fail();
    }

    try {
      new HotpAuthOptions()
        .setPasswordLength(7);
    } catch (IllegalArgumentException e) {
      should.fail();
    }

    try {
      new HotpAuthOptions()
        .setPasswordLength(8);
    } catch (IllegalArgumentException e) {
      should.fail();
    }

    try {
      new HotpAuthOptions()
        .setPasswordLength(9);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
      .setPasswordLength(10);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(Integer.MAX_VALUE);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(Integer.MIN_VALUE);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setLookAheadWindow(-1);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setLookAheadWindow(Integer.MIN_VALUE);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setLookAheadWindow(5);
      should.assertTrue(hotpAuthOptions.isUsingResynchronization());
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setLookAheadWindow(0);
      should.assertFalse(hotpAuthOptions.isUsingResynchronization());
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setAuthAttemptsLimit(-1);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setAuthAttemptsLimit(Integer.MIN_VALUE);
      should.fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setAuthAttemptsLimit(5);
      should.assertTrue(hotpAuthOptions.isUsingAttemptsLimit());
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setAuthAttemptsLimit(0);
      should.assertFalse(hotpAuthOptions.isUsingAttemptsLimit());
    } catch (IllegalArgumentException ignore) {}
  }
}
