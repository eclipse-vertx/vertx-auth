package io.vertx.ext.auth.mongo;

import io.vertx.codegen.annotations.VertxGen;

@VertxGen
public enum HashAlgorithm {
  /**
   * The default algorithm for backward compatible systems.
   *
   * Should not be used for new projects as OWASP recommends stronger hashing algorithms.
   */
  SHA512,

  /**
   * Stronger hashing algorithm, recommended by OWASP as of 2018.
   */
  PBKDF2
}
