package io.vertx.kotlin.ext.auth.mongo

import io.vertx.ext.auth.mongo.MongoAuthOptions
import io.vertx.ext.auth.mongo.HashSaltStyle

fun MongoAuthOptions(
        collectionName: String? = null,
    config: io.vertx.core.json.JsonObject? = null,
    datasourceName: String? = null,
    passwordField: String? = null,
    permissionField: String? = null,
    roleField: String? = null,
    saltField: String? = null,
    saltStyle: HashSaltStyle? = null,
    shared: Boolean? = null,
    usernameCredentialField: String? = null,
    usernameField: String? = null): MongoAuthOptions = io.vertx.ext.auth.mongo.MongoAuthOptions().apply {

    if (collectionName != null) {
        this.collectionName = collectionName
    }

    if (config != null) {
        this.config = config
    }

    if (datasourceName != null) {
        this.datasourceName = datasourceName
    }

    if (passwordField != null) {
        this.passwordField = passwordField
    }

    if (permissionField != null) {
        this.permissionField = permissionField
    }

    if (roleField != null) {
        this.roleField = roleField
    }

    if (saltField != null) {
        this.saltField = saltField
    }

    if (saltStyle != null) {
        this.saltStyle = saltStyle
    }

    if (shared != null) {
        this.shared = shared
    }

    if (usernameCredentialField != null) {
        this.usernameCredentialField = usernameCredentialField
    }

    if (usernameField != null) {
        this.usernameField = usernameField
    }

}

