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

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.HashingAlgorithmHolder;

import java.util.Collections;
import java.util.Set;

/**
 * Hashing Algorithm. A common interface to interact with any system provided algorithms.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface HashingAlgorithm {


  static HashingAlgorithm getById(String id) {
    return HashingAlgorithmHolder.getById(id);
  }

  static HashingAlgorithm getByAlgorithm(String algorithm) {
    return HashingAlgorithmHolder.getByAlgorithm(algorithm);
  }

  /**
   * return the symbolic name for the algorithm
   *
   * @return short id e.g.: sha512.
   */
  String id();


  /**
   * return the official algorithm name
   *
   * @return short id e.g.: SHA-512.
   */
  String algorithm();

  /**
   * return the list of param names required for this algorithm.
   *
   * @return set of param names.
   */
  default Set<String> params()  {
    return Collections.emptySet();
  }

  /**
   * Algorithm specific implementation.
   *
   * @return the hashed digest.
   */
  @GenIgnore
  String hash(HashString hashString, String password);

  /**
   * Algorithm specific implementation.
   *
   * @return the hashed digest.
   */
  @GenIgnore
  default byte[] hash(byte[] rawValue) {
    throw new UnsupportedOperationException();
  }

  /**
   * Should the encoded string use the default separator to split fields.
   * @return true by default.
   */
  default boolean needsSeparator() {
    return true;
  }
}
