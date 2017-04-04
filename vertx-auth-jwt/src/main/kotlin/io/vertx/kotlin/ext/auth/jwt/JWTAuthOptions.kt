package io.vertx.kotlin.ext.auth.jwt

import io.vertx.ext.auth.jwt.JWTAuthOptions
import io.vertx.ext.auth.jwt.JWTKeyStoreOptions

/**
 * A function providing a DSL for building [io.vertx.ext.auth.jwt.JWTAuthOptions] objects.
 *
 * Options describing how an JWT Auth should behave.
 *
 * @param audience  Set the audience list
 * @param audiences  Set the audience list
 * @param ignoreExpiration  Set whether expiration is ignored
 * @param issuer  Set the issuer
 * @param keyStore 
 * @param permissionsClaimKey 
 * @param publicKey 
 *
 * <p/>
 * NOTE: This function has been automatically generated from the [io.vertx.ext.auth.jwt.JWTAuthOptions original] using Vert.x codegen.
 */
fun JWTAuthOptions(
  audience: Iterable<String>? = null,
  audiences: Iterable<String>? = null,
  ignoreExpiration: Boolean? = null,
  issuer: String? = null,
  keyStore: io.vertx.ext.auth.jwt.JWTKeyStoreOptions? = null,
  permissionsClaimKey: String? = null,
  publicKey: String? = null): JWTAuthOptions = io.vertx.ext.auth.jwt.JWTAuthOptions().apply {

  if (audience != null) {
    this.setAudience(audience.toList())
  }
  if (audiences != null) {
    for (item in audiences) {
      this.addAudience(item)
    }
  }
  if (ignoreExpiration != null) {
    this.setIgnoreExpiration(ignoreExpiration)
  }
  if (issuer != null) {
    this.setIssuer(issuer)
  }
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

