package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

@VertxGen
public interface WebAuthNStore {

  @Fluent
  WebAuthNStore find(String id, Handler<AsyncResult<JsonObject>> handler);

  @Fluent
  WebAuthNStore update(String id, JsonObject data, Handler<AsyncResult<JsonObject>> handler);
}
