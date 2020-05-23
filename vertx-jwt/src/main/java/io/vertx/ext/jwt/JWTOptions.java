package io.vertx.ext.jwt;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * @deprecated In 4.0.0 this module will be merged with vertx-auth-common, for this reason this class should be found
 * in the common module, instead of here. Changing the import should fix any deprecations.
 */
@Deprecated
@DataObject
public class JWTOptions extends io.vertx.ext.auth.JWTOptions {

  public JWTOptions() {
    super();
  }

  public JWTOptions(JsonObject json) {
    super(json);
  }
}
