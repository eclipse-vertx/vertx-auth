package io.vertx.kotlin.ext.auth.jdbc

import io.vertx.ext.auth.jdbc.JDBCAuthOptions

fun JDBCAuthOptions(
    authenticationQuery: String? = null,
  config: io.vertx.core.json.JsonObject? = null,
  datasourceName: String? = null,
  permissionsQuery: String? = null,
  rolesPrefix: String? = null,
  rolesQuery: String? = null,
  shared: Boolean? = null): JDBCAuthOptions = io.vertx.ext.auth.jdbc.JDBCAuthOptions().apply {

  if (authenticationQuery != null) {
    this.authenticationQuery = authenticationQuery
  }

  if (config != null) {
    this.config = config
  }

  if (datasourceName != null) {
    this.datasourceName = datasourceName
  }

  if (permissionsQuery != null) {
    this.permissionsQuery = permissionsQuery
  }

  if (rolesPrefix != null) {
    this.rolesPrefix = rolesPrefix
  }

  if (rolesQuery != null) {
    this.rolesQuery = rolesQuery
  }

  if (shared != null) {
    this.isShared = shared
  }

}

