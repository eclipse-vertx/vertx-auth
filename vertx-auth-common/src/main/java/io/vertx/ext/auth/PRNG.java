/*
 * Copyright 2014 Red Hat, Inc.
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

import io.vertx.core.Vertx;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

import static io.vertx.ext.auth.impl.Codec.base64UrlEncode;

/**
 * Wrapper around secure random that periodically seeds the PRNG with new entropy. To avoid entropy exhaustion
 * the entropy is only refreshed if the PRNG is used. This introduces a new variable which reduces the probability
 * of cracking the random number generator.
 *
 * @author Paulo Lopes
 * @deprecated this class should not be used directly and should be package private
 */
@Deprecated
public class PRNG implements VertxContextPRNG {

  private static final int DEFAULT_SEED_INTERVAL_MILLIS = 300000;
  private static final int DEFAULT_SEED_BITS = 64;

  private final SecureRandom random;
  private final long seedID;

  private final Vertx vertx;
  // Track if the current seed has been used for random number generation
  private volatile boolean dirty = false;

  public PRNG(Vertx vertx) {
    this.vertx = vertx;

    final String algorithm = System.getProperty("io.vertx.ext.auth.prng.algorithm");
    final int seedInterval = Integer.getInteger("io.vertx.ext.auth.prng.seed.interval", DEFAULT_SEED_INTERVAL_MILLIS);
    final int seedBits = Integer.getInteger("io.vertx.ext.auth.prng.seed.bits", DEFAULT_SEED_BITS);

    if (algorithm != null) {
      // the user has made a conscious decision to not use the JVM defaults
      try {
        random = SecureRandom.getInstance(algorithm);
      } catch (NoSuchAlgorithmException e) {
        // the algorithm is not available
        throw new RuntimeException(e);
      }
    } else {
      // initialize a secure random (note that on unices JDK8 will default to a mixed mode nativeprng
      // (non-blocking for getBytes() blocking for generateSeed()). A similar behavior is expected with SHA1PRNG which
      // will be the fallback on Windows
      random = new SecureRandom();
    }

    // Make sure default seeding happens now to avoid calling setSeed() too early
    random.nextBytes(new byte[1]);

    // seed internal and bits must be enabled
    if (seedInterval > 0 && seedBits > 0) {
      final AtomicBoolean seeding = new AtomicBoolean(false);
      // Add a 64bit entropy every five minutes
      // see: https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Session_ID_Entropy
      seedID = vertx.setPeriodic(
        seedInterval,
        id -> {
          if (dirty && seeding.compareAndSet(false, true)) {
            vertx.<byte[]>executeBlocking(
              future -> future.complete(random.generateSeed(seedBits / 8)),
              false,
              generateSeed -> {
                seeding.set(false);
                dirty = false;
                random.setSeed(generateSeed.result());
              });
          }
        });
    } else {
      seedID = -1;
    }
  }


  @Override
  public void close() {
    if (seedID != -1) {
      vertx.cancelTimer(seedID);
    }
  }

  @Override
  public void nextBytes(byte[] bytes) {
    if (bytes != null) {
      random.nextBytes(bytes);
      dirty = true;
    }
  }

  @Override
  public int nextInt() {
    try {
      return random.nextInt();
    } finally {
      dirty = true;
    }
  }

  @Override
  public int nextInt(final int bound) {
    try {
      return random.nextInt(bound);
    } finally {
      dirty = true;
    }
  }

  @Override
  public boolean nextBoolean() {
    try {
      return random.nextBoolean();
    } finally {
      dirty = true;
    }
  }

  @Override
  public long nextLong() {
    try {
      return random.nextLong();
    } finally {
      dirty = true;
    }
  }

  @Override
  public float nextFloat() {
    try {
      return random.nextFloat();
    } finally {
      dirty = true;
    }
  }

  @Override
  public double nextDouble() {
    try {
      return random.nextDouble();
    } finally {
      dirty = true;
    }
  }

  @Override
  public double nextGaussian() {
    try {
      return random.nextGaussian();
    } finally {
      dirty = true;
    }
  }

  @Override
  public String nextString(int length) {
    // create buffer
    final byte[] data = new byte[length];
    // fill with random data
    nextBytes(data);
    // encode
    return base64UrlEncode(data);
  }

}
