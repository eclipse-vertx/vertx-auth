package io.vertx.kotlin.ext.auth.shiro

import io.vertx.ext.auth.shiro.ShiroAuthOptions
import io.vertx.ext.auth.shiro.ShiroAuthRealmType

fun ShiroAuthOptions(
        config: io.vertx.core.json.JsonObject? = null,
    type: ShiroAuthRealmType? = null): ShiroAuthOptions = io.vertx.ext.auth.shiro.ShiroAuthOptions().apply {

    if (config != null) {
        this.config = config
    }

    if (type != null) {
        this.type = type
    }

}

