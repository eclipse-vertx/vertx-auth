package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import io.vertx.core.spi.json.JsonDecoder;

/**
 * Converter and Codec for {@link io.vertx.ext.auth.jwt.JWTOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTOptions} original class using Vert.x codegen.
 */
public class JWTOptionsConverter implements JsonDecoder<JWTOptions, JsonObject> {

  public static final JWTOptionsConverter INSTANCE = new JWTOptionsConverter();

  @Override public JWTOptions decode(JsonObject value) { return (value != null) ? new JWTOptions(value) : null; }

  @Override public Class<JWTOptions> getTargetClass() { return JWTOptions.class; }
}
