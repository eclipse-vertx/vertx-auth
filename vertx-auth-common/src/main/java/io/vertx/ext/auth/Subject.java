/*
 * Copyright 2021 Red Hat, Inc.
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

import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;

/**
 * Represents a Subject and optionally the acting parties involved in a delegation process for a user.

 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface Subject {

  String subject();

  /**
   * The actor claim provides a means to express that delegation has occurred and identify the acting party to whom
   * authority has been delegated.
   * @return the delegated subject
   */
  @Nullable Subject actor();

  /**
   * The may act for claim provides a means to express that delegation has occurred and identify the acting party to
   * whom authority has been delegated (yet it is not guaranteed that it will be allowed).
   * @return the delegated subject
   */
  @Nullable Subject mayActFor();

  /**
   * Get a value from the Subject object.
   * @param key the key to look up
   * @param <T> the expected type
   * @return the value or null if missing
   * @throws ClassCastException if the value cannot be cast to {@code T}
   */
  <T> @Nullable T get(String key);

  /**
   * Checks if a value exists on the user object.
   * @param key the key to look up
   * @return the value or null if missing
   */
  boolean containsKey(String key);
}
