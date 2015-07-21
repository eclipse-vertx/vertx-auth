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

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.User;

/**
 * Determines how the hashing is computed in the implementation You can implement this to provide a different hashing
 * strategy to the default.
 *
 * @author mremme
 */
@VertxGen
public interface HashStrategy {

  /**
   * Password hash salt configuration.
   * <ul>
   * <li>NO_SALT - password hashes are not salted.</li>
   * <li>COLUMN - salt is in a separate column for each user in the database.</li>
   * <li>EXTERNAL - salt is NOT stored in the database, but defined as external value like application preferences or so
   * </li>
   * </ul>
   */
  public enum SaltStyle {
    NO_SALT, COLUMN, EXTERNAL;
  };

  /**
   * Compute the hashed password given the unhashed password and the user
   * 
   * @param password
   *          the unhashed password
   * @param user
   *          the user to get the salt for. This paramter is needed, if the {@link SaltStyle#COLUMN} is declared to be
   *          used
   * @return the hashed password
   */
  String computeHash(String password, User user);

  /**
   * Retrieve the password from the user, or as clear text or as hashed version, depending on the definition
   * 
   * @param user
   *          the user to get the stored password for
   * @return the password, either as hashed version or as cleartext, depending on the preferences
   */
  String getStoredPwd(User user);

  /**
   * Retrieve the salt. The source of the salt can be the external salt or the propriate column of the given user,
   * depending on the defined {@link SaltStyle}
   * 
   * @param user
   *          the user to get the salt for. This paramter is needed, if the {@link SaltStyle#COLUMN} is declared to be
   *          used
   * @return null in case of {@link SaltStyle#NO_SALT} the salt of the user or a defined external salt
   */
  String getSalt(User user);

  /**
   * Set an external salt. This method should be used in case of {@link SaltStyle#EXTERNAL}
   * 
   * @param salt
   *          the salt, which shall be used
   */
  void setExternalSalt(String salt);

  /**
   * Set the saltstyle as defined by {@link SaltStyle}.
   * 
   * @param saltStyle
   *          the {@link SaltStyle} to be used
   */
  public void setSaltStyle(SaltStyle saltStyle);

  /**
   * Get the defined {@link SaltStyle} of the current instance
   * 
   * @return the saltStyle
   */
  public SaltStyle getSaltStyle();

}
