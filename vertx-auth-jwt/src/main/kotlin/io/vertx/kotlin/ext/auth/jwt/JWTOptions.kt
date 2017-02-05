package io.vertx.kotlin.ext.auth.jwt

import io.vertx.ext.auth.jwt.JWTOptions

/**
 * A function providing a DSL for building [io.vertx.ext.auth.jwt.JWTOptions] objects.
 *
 * Options related to creation of new tokens.
 *
 * If any expiresInMinutes, audience, subject, issuer are not provided, there is no default.
 * The jwt generated won't include those properties in the payload.
 *
 * Generated JWTs will include an iat claim by default unless noTimestamp is specified.
 *
 * @param algorithm  The algorithm to use, it should be one of the alias [HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512]
 * @param audience  The target audience of this token
 * @param audiences  The target audience of this token
 * @param expiresInMinutes  The expiration time for the token in minutes
 * @param expiresInSeconds  The expiration time for the token in seconds
 * @param headers 
 * @param issuer  The issuer of this token
 * @param noTimestamp  Disable the generation of issued at claim
 * @param permissions  The permissions of this token.
 * @param subject  The subject of this token
 *
 * <p/>
 * NOTE: This function has been automatically generated from the [io.vertx.ext.auth.jwt.JWTOptions original] using Vert.x codegen.
 */
fun JWTOptions(
  algorithm: String? = null,
  audience: Iterable<String>? = null,
  audiences: Iterable<String>? = null,
  expiresInMinutes: Long? = null,
  expiresInSeconds: Long? = null,
  headers: Map<String, String>? = null,
  issuer: String? = null,
  noTimestamp: Boolean? = null,
  permissions: Iterable<String>? = null,
  subject: String? = null): JWTOptions = io.vertx.ext.auth.jwt.JWTOptions().apply {

  if (algorithm != null) {
    this.setAlgorithm(algorithm)
  }
  if (audience != null) {
    this.setAudience(audience.toList())
  }
  if (audiences != null) {
    for (item in audiences) {
      this.addAudience(item)
    }
  }
  if (expiresInMinutes != null) {
    this.setExpiresInMinutes(expiresInMinutes)
  }
  if (expiresInSeconds != null) {
    this.setExpiresInSeconds(expiresInSeconds)
  }
  if (headers != null) {
    for (item in headers) {
      this.addHeader(item.key, item.value)
    }
  }
  if (issuer != null) {
    this.setIssuer(issuer)
  }
  if (noTimestamp != null) {
    this.setNoTimestamp(noTimestamp)
  }
  if (permissions != null) {
    this.setPermissions(permissions.toList())
  }
  if (subject != null) {
    this.setSubject(subject)
  }
}

