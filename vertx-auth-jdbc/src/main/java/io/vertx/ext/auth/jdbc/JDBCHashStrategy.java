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

package io.vertx.ext.auth.jdbc;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jdbc.impl.PBKDF2Strategy;
import io.vertx.ext.auth.jdbc.impl.SHA512Strategy;

/**
 * Determines how the hashing is computed in the implementation
 *
 * You can implement this to provide a different hashing strategy to the default.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface JDBCHashStrategy {

  /**
   * This is the current backwards compatible hashing implementation, new applications should prefer the
   * PBKDF2 implementation, unless the tradeoff between security and CPU usage is an option.
   *
   * @param vertx the vert.x instance
   * @return the implementation.
   */
  static JDBCHashStrategy createSHA512(Vertx vertx) {
    return new SHA512Strategy(vertx);
  }

  /**
   * Implements a Hashing Strategy as per https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet (2018-01-17).
   *
   * New deployments should use this strategy instead of the default one (which was the previous OWASP recommendation).
   *
   * The work factor can be updated by using the nonces json array.
   *
   * @param vertx the vert.x instance
   * @return the implementation.
   */
  static JDBCHashStrategy createPBKDF2(Vertx vertx) {
    return new PBKDF2Strategy(vertx);
  }

  /**
   * Compute a random salt.
   *
   * @return a non null salt value
   */
  String generateSalt();

  /**
   * Compute the hashed password given the unhashed password and the salt
   * @param password  the unhashed password
   * @param salt  the salt
   * @param version the nonce version to use
   * @return  the hashed password
   */
  String computeHash(String password, String salt, int version);

  /**
   * Retrieve the hashed password from the result of the authentication query
   * @param row  the row
   * @return  the hashed password
   */
  String getHashedStoredPwd(JsonArray row);

  /**
   * Retrieve the salt from the result of the authentication query
   * @param row  the row
   * @return  the salt
   */
  String getSalt(JsonArray row);

  /**
   * Sets a ordered list of nonces where each position corresponds to a version.
   *
   * The nonces are supposed not to be stored in the underlying jdbc storage but to
   * be provided as a application configuration. The idea is to add one extra variable
   * to the hash function in order to make breaking the passwords using rainbow tables
   * or precomputed hashes harder. Leaving the attacker only with the brute force
   * approach.
   *
   * Nonces are dependent on the implementation. E.g.: for the SHA512 they are extra salt
   * used during the hashing, for the PBKDF2 they map the number of iterations the algorithm
   * should take
   *
   * @param nonces a json array.
   */
  void setNonces(JsonArray nonces);

  /**
   * Time constant string comparision to avoid timming attacks.
   *
   * @param hasha hash a to compare
   * @param hashb hash b to compare
   * @return true if equal
   */
  static boolean isEqual(final String hasha, final String hashb) {
    int diff = hasha.length() ^ hashb.length();
    for(int i = 0; i < hasha.length() && i < hashb.length(); i++) {
      diff |= hasha.charAt(i) ^ hashb.charAt(i);
    }
    return diff == 0;
  }
}
