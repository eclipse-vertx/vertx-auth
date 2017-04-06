/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Context;
import io.vertx.core.Vertx;

import java.util.Base64;

/**
 *
 * A secure non blocking random number generator isolated to the current context. The PRNG is bound to the vert.x
 * context and setup to close when the context shuts down.
 *
 * When applicable, use of VertxContextRandom rather than create new PRNG objects is helpful to keep the system entropy
 * usage to the minimum avoiding potential blocking across the application.
 *
 * The use of VertxContextRandom is particularly appropriate when multiple handlers use random numbers.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface VertxContextRandom {

  /**
   * Get or create a secure non blocking random number generator using the current vert.x context. If there is no
   * current context (i.e.: not running on the eventloop) then a {@link java.lang.IllegalStateException} is thrown.
   *
   * @return A secure non blocking random number generator.
   * @throws IllegalStateException when there is no context available.
   */
  static VertxContextRandom current() {
    final Context currentContext = Vertx.currentContext();
    if (currentContext != null) {
      return current(currentContext.owner());
    }

    throw new IllegalStateException("Not running in a Vert.x Context.");
  }

  /**
   * Get or create a secure non blocking random number generator using the current vert.x context. This method will not
   * throw an exception.
   *
   * @return A secure non blocking random number generator.
   * @param vertx a Vert.x instance.
   */
  static VertxContextRandom current(final Vertx vertx) {
    // try to get the current context
    Context currentContext = Vertx.currentContext();
    if (currentContext == null) {
      currentContext = vertx.getOrCreateContext();
    }
    // attempt to load a PRNG from the current context
    PRNG random = currentContext.get(VertxContextRandom.class.getName());

    if (random == null) {
      synchronized (currentContext) {
        // attempt to reload to avoid double creation when we were
        // waiting for the lock
        random = currentContext.get(VertxContextRandom.class.getName());
        if (random == null) {
          // there was no PRNG in the context, create one
          random = new PRNG(vertx);
          // need to make the random final
          final PRNG rand = random;
          // save to the context
          currentContext.put(VertxContextRandom.class.getName(), rand);
          // add a close hook to shutdown the PRNG
          currentContext.addCloseHook(v -> rand.close());
        }
      }
    }

    return random;
  }

  /**
   * Fills the given byte array with random bytes.
   *
   * @param bytes a byte array.
   */
  @GenIgnore
  void nextBytes(byte[] bytes);

  /**
   * Returns a Base64 mime encoded String of random data with the given length. The length parameter refers to the length
   * of the String before the encoding step.
   *
   * @param length the desired string length before Base64 encoding.
   * @return A base 64 encoded string.
   */
  default String nextString(int length) {
    // create buffer
    final byte[] data = new byte[length];
    // fill with random data
    nextBytes(data);
    // encode
    return Base64.getMimeEncoder().encodeToString(data);
  }

  /**
   * Returns a secure random int
   *
   * @return random int.
   */
  int nextInt();
}
