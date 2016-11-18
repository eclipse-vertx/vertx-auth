package io.vertx.kotlin.ext.auth.jwt

import io.vertx.ext.auth.jwt.JWTOptions

fun JWTOptions(
        algorithm: String? = null,
    audience: List<String>? = null,
    expiresInMinutes: Long? = null,
    expiresInSeconds: Long? = null,
    issuer: String? = null,
    noTimestamp: Boolean? = null,
    subject: String? = null): JWTOptions = io.vertx.ext.auth.jwt.JWTOptions().apply {

    if (algorithm != null) {
        this.algorithm = algorithm
    }

    if (audience != null) {
        this.audience = audience
    }

    if (expiresInMinutes != null) {
        this.expiresInMinutes = expiresInMinutes
    }

    if (expiresInSeconds != null) {
        this.expiresInSeconds = expiresInSeconds
    }

    if (issuer != null) {
        this.issuer = issuer
    }

    if (noTimestamp != null) {
        this.noTimestamp = noTimestamp
    }

    if (subject != null) {
        this.subject = subject
    }

}

