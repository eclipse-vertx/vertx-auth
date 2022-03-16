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

import java.util.Objects;

import static io.vertx.codegen.annotations.GenIgnore.PERMITTED_TYPE;

/**
 * A secure non blocking random number generator isolated to the current context. The PRNG is bound to the vert.x
 * context and setup to close when the context shuts down.
 * <p>
 * When applicable, use of VertxContextPRNG rather than create new PRNG objects is helpful to keep the system entropy
 * usage to the minimum avoiding potential blocking across the application.
 * <p>
 * The use of VertxContextPRNG is particularly appropriate when multiple handlers use random numbers.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface VertxContextPRNG {

  /**
   * Get or create a secure non blocking random number generator using the current vert.x context. If there is no
   * current context (i.e.: not running on the eventloop) then a {@link java.lang.IllegalStateException} is thrown.
   *
   * Note, if a context isn't allowed to be used, for example, exceptions are thrown on getting and putting data,
   * the VertxContextPRNG falls back to instantiate a new instance of the PRNG per call.
   *
   * @return A secure non blocking random number generator.
   * @throws IllegalStateException when there is no {@link Context} instance available.
   */
  static VertxContextPRNG current() {
    final Context currentContext = Vertx.currentContext();
    if (currentContext != null) {
      return current(currentContext);
    }

    throw new IllegalStateException("Not running in a Vert.x Context.");
  }

  /**
   * Get or create a secure non blocking random number generator using the provided vert.x context. This method will not
   * throw an exception.
   *
   * Note, if a context isn't allowed to be used, for example, exceptions are thrown on getting and putting data,
   * the VertxContextPRNG falls back to instantiate a new instance of the PRNG per call.
   *
   * @param context a Vert.x context.
   * @return A secure non blocking random number generator
   * @throws IllegalStateException when there is no {@link Vertx} instance available.
   */
  @GenIgnore
  static VertxContextPRNG current(final Context context) {
    Objects.requireNonNull(context, "context can not be null");

    try {
      final String contextKey = "__vertx.VertxContextPRNG";
      // attempt to load a PRNG from the current context
      PRNG random = context.get(contextKey);

      if (random == null) {
        synchronized (context) {
          // attempt to reload to avoid double creation when we were
          // waiting for the lock
          random = context.get(contextKey);
          if (random == null) {
            // there was no PRNG in the context, create one
            random = new PRNG(context.owner());
            // need to make the random final
            final PRNG rand = random;
            // save to the context
            context.put(contextKey, rand);
          }
        }
      }

      return random;
    } catch (UnsupportedOperationException e) {
      // Access to the current context is probably blocked
      Vertx vertx = context.owner();
      if (vertx != null) {
        return new PRNG(vertx);
      }
      // vert.x cannot be null
      throw new IllegalStateException("Not running in a Vert.x Context.");
    }
  }

  /**
   * Get or create a secure non blocking random number generator using the current vert.x instance. Since the context
   * might be different this method will attempt to use the current context first if available and then fall back to
   * create a new instance of the PRNG.
   *
   * Note, if a context isn't allowed to be used, for example, exceptions are thrown on getting and putting data,
   * the VertxContextPRNG falls back to instantiate a new instance of the PRNG per call.
   *
   * @param vertx a Vert.x instance.
   * @return A secure non blocking random number generator.
   */
  static VertxContextPRNG current(final Vertx vertx) {
    final Context currentContext = Vertx.currentContext();
    if (currentContext != null) {
      return current(currentContext);
    }

    Objects.requireNonNull(vertx, "vertx can not be null");
    // we are not running on a vert.x context, fallback to create a new instance
    return new PRNG(vertx);
  }

  /**
   * stop seeding the PRNG
   */
  void close();

  /**
   * Fills the given byte array with random bytes.
   *
   * @param bytes a byte array.
   */
  @GenIgnore(PERMITTED_TYPE)
  void nextBytes(byte[] bytes);

  /**
   * Returns a Base64 url encoded String of random data with the given length. The length parameter refers to the length
   * of the String before the encoding step.
   *
   * @param length the desired string length before Base64 encoding.
   * @return A base 64 encoded string.
   */
  String nextString(int length);

  /**
   * Returns a secure random int
   *
   * @return random int.
   */
  int nextInt();

  /**
   * Returns a secure random int, between 0 (inclusive) and the specified bound (exclusive).
   *
   * @param bound the upper bound (exclusive), which must be positive.
   * @return random int.
   */
  int nextInt(int bound);


  /**
   * Returns a secure random boolean
   *
   * @return random boolean.
   */
  boolean nextBoolean();


  /**
   * Returns a secure random long
   *
   * @return random long.
   */
  long nextLong();


  /**
   * Returns a secure random float value. The value is uniformly distributed between 0.0 and 1.0
   *
   * @return random float.
   */
  float nextFloat();


  /**
   * Returns a secure random double value. The value is uniformly distributed between 0.0 and 1.0
   *
   * @return random double.
   */
  double nextDouble();


  /**
   * Returns a secure random double value. The value is Gaussian ("normally") distributed
   * with mean 0.0 and standard deviation 1.0
   *
   * @return random double.
   */
  double nextGaussian();
}
