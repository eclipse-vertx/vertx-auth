package io.vertx.kotlin.ext.auth.jwt

import io.vertx.ext.auth.KeyStoreOptions

/**
 * A function providing a DSL for building [io.vertx.ext.auth.jwt.KeyStoreOptions] objects.
 *
 * Options describing how an JWT KeyStore should behave.
 *
 * @param password
 * @param path
 * @param type
 *
 * <p/>
 * NOTE: This function has been automatically generated from the [io.vertx.ext.auth.KeyStoreOptions original] using Vert.x codegen.
 */
fun JWTKeyStoreOptions(
  password: String? = null,
  path: String? = null,
  type: String? = null): KeyStoreOptions = KeyStoreOptions().apply {

  if (password != null) {
    this.setPassword(password)
  }
  if (path != null) {
    this.setPath(path)
  }
  if (type != null) {
    this.setType(type)
  }
}

