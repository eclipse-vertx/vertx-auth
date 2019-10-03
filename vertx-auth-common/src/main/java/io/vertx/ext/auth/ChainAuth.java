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

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.ChainAuthImpl;

/**
 * Chain several auth providers as if they were one. This is useful for cases where one want to authenticate across
 * several providers, for example, database and fallback to passwd file.
 */
@VertxGen
public interface ChainAuth extends AuthProvider {

  /**
   * Create a Chainable Auth Provider auth provider
   *
   * @return the auth provider
   */
  static ChainAuth create() {
    return new ChainAuthImpl();
  }


  /**
   * {@inheritDoc}
   */
  @Override
  default String id() {
    return ChainAuth.class.getName();
  }

  /**
   * Appends a auth provider to the chain.
   *
   * @param other auth provider
   * @return self
   */
  @Fluent
  ChainAuth append(AuthProvider other);

  /**
   * Removes a provider from the chain.
   * @param other provider to remove
   * @return true if provider was removed, false if non existent in the chain.
   */
  boolean remove(AuthProvider other);

  /**
   * Clears the chain.
   */
  void clear();
}
