package io.vertx.kotlin.ext.auth.jwt

import io.vertx.ext.auth.jwt.JWTAuthOptions
import io.vertx.ext.auth.KeyStoreOptions
import io.vertx.ext.auth.PubSecKeyOptions
import io.vertx.ext.auth.SecretOptions

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
 * @param pubSecKeys 
 * @param secrets 
 *
 * <p/>
 * NOTE: This function has been automatically generated from the [io.vertx.ext.auth.jwt.JWTAuthOptions original] using Vert.x codegen.
 */
fun JWTAuthOptions(
  audience: Iterable<String>? = null,
  audiences: Iterable<String>? = null,
  ignoreExpiration: Boolean? = null,
  issuer: String? = null,
  keyStore: io.vertx.ext.auth.KeyStoreOptions? = null,
  permissionsClaimKey: String? = null,
  pubSecKeys: Iterable<io.vertx.ext.auth.PubSecKeyOptions>? = null,
  secrets: Iterable<io.vertx.ext.auth.SecretOptions>? = null): JWTAuthOptions = io.vertx.ext.auth.jwt.JWTAuthOptions().apply {

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
  if (pubSecKeys != null) {
    this.setPubSecKeys(pubSecKeys.toList())
  }
  if (secrets != null) {
    this.setSecrets(secrets.toList())
  }
}

