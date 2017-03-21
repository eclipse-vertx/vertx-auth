package io.vertx.kotlin.ext.auth.jwt

import io.vertx.ext.auth.jwt.JWTAuthOptions
import io.vertx.ext.auth.jwt.JWTKeyStoreOptions

/**
 * A function providing a DSL for building [io.vertx.ext.auth.jwt.JWTAuthOptions] objects.
 *
 * Options describing how an JWT Auth should behave.
 *
 * @param keyStore 
 * @param permissionsClaimKey 
 * @param publicKey 
 *
 * <p/>
 * NOTE: This function has been automatically generated from the [io.vertx.ext.auth.jwt.JWTAuthOptions original] using Vert.x codegen.
 */
fun JWTAuthOptions(
  keyStore: io.vertx.ext.auth.jwt.JWTKeyStoreOptions? = null,
  permissionsClaimKey: String? = null,
  publicKey: String? = null): JWTAuthOptions = io.vertx.ext.auth.jwt.JWTAuthOptions().apply {

  if (keyStore != null) {
    this.setKeyStore(keyStore)
  }
  if (permissionsClaimKey != null) {
    this.setPermissionsClaimKey(permissionsClaimKey)
  }
  if (publicKey != null) {
    this.setPublicKey(publicKey)
  }
}

