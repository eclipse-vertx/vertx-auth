/*
 * Copyright 2014 Red Hat, Inc.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 * 
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 * 
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.mongo;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;

import java.util.List;

/**
 * UserFactory is used by an AuthProvider to create an instance of {@link User}. By using this interface one can use own
 * implementations of {@link User} without changing the {@link AuthProvider} itself. Additionally the factory methods
 * should provide needed automatisms in the creation of a user
 * 
 * @author mremme
 */

public interface UserFactory {

  /**
   * Create an instance of {@link User} This method is used to create a new instance of a user from the scratch.
   * 
   * @param username
   * @param authProvider
   * @return
   */
  public User createUser(String username, AuthProvider authProvider);

  /**
   * Create an instance of {@link User}.
   * This method is used to create a new instance of a user from the scratch. Thus, here are executed some automatisms
   * like
   * salt creation, password encryption if the properties define that.
   * If the given password is null, it should be autocreated
   * 
   * @param username
   *          the username to be used
   * @param password
   *          the password in clear text. If null is given, it will be autocreated.
   * @roles
   *        the roles as list, where the user is belonging to
   * @permissions
   *              the permissions as list, where the user is belonging to
   * @param authProvider
   * @return
   */
  public User createUser(String username, String password, List<String> roles, List<String> permissions,
      AuthProvider authProvider);

  /**
   * Create an instance of {@link User}.
   * This method is NOT performing automatisms like password encryption, cause it can be used for already existing, from
   * database loaded users
   * 
   * @param principal
   * @param authProvider
   * @return
   */
  public User createUser(JsonObject principal, AuthProvider authProvider);

}
