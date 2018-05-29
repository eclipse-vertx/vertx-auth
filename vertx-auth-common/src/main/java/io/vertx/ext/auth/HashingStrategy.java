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

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.HashingStrategyImpl;

import java.util.Map;
import java.util.ServiceLoader;

/**
 * Hashing Strategy manager.
 *
 * This class will load system provided hashing strategies and algorithms.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface HashingStrategy {

  static HashingStrategy load() {
    final HashingStrategyImpl strategy = new HashingStrategyImpl();
    ServiceLoader<HashingAlgorithm> serviceLoader = ServiceLoader.load(HashingAlgorithm.class);

    for (HashingAlgorithm algorithm : serviceLoader) {
      strategy.add(algorithm);
    }

    return strategy;
  }

  String hash(String id, Map<String, String> params, String salt, String password);

  boolean verify(String hash, String password);

  HashingAlgorithm get(String id);

  HashingStrategy put(String id, HashingAlgorithm algorithm);
}
