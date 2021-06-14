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

package io.vertx.ext.auth.otp;

import io.vertx.ext.auth.otp.hotp.HotpAuthOptions;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class HotpAuthOptionsTest extends VertxTestBase {

  @Test
  public void test1() {
    try {
      new HotpAuthOptions()
        .setPasswordLength(0);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(5);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(6);
    } catch (IllegalArgumentException e) {
      fail();
    }

    try {
      new HotpAuthOptions()
        .setPasswordLength(7);
    } catch (IllegalArgumentException e) {
      fail();
    }

    try {
      new HotpAuthOptions()
        .setPasswordLength(8);
    } catch (IllegalArgumentException e) {
      fail();
    }

    try {
      new HotpAuthOptions()
        .setPasswordLength(9);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
      .setPasswordLength(10);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(Integer.MAX_VALUE);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setPasswordLength(Integer.MIN_VALUE);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setLookAheadWindow(-1);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setLookAheadWindow(Integer.MIN_VALUE);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setLookAheadWindow(5);
      assertTrue(hotpAuthOptions.isUsingResynchronization());
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setLookAheadWindow(0);
      assertFalse(hotpAuthOptions.isUsingResynchronization());
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setAuthAttemptsLimit(-1);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      new HotpAuthOptions()
        .setAuthAttemptsLimit(Integer.MIN_VALUE);
      fail();
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setAuthAttemptsLimit(5);
      assertTrue(hotpAuthOptions.isUsingAttemptsLimit());
    } catch (IllegalArgumentException ignore) {}

    try {
      final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
        .setAuthAttemptsLimit(0);
      assertFalse(hotpAuthOptions.isUsingAttemptsLimit());
    } catch (IllegalArgumentException ignore) {}
  }
}
