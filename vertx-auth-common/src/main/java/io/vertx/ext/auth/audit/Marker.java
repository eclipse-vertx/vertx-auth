package io.vertx.ext.auth.audit;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@VertxGen
public enum Marker {

  SECURITY(true, "password", "secret"),
  EVENT(false, "password", "secret"),
  AUDIT(true, "password", "secret", "sub", "jwt", "username");

  private final Logger logger = LoggerFactory.getLogger("io.vertx.ext.auth.audit." + name().toLowerCase());

  private final boolean signed;
  private final Set<String> masked = new HashSet<>();

  private Marker(boolean signed, String... maskedKeys) {
    this.signed = signed;
    if (maskedKeys != null) {
      Collections.addAll(masked, maskedKeys);
    }
  }

  public Logger logger() {
    return logger;
  }

  public boolean signed() {
    return signed;
  }

  public boolean mask(String key) {
    return masked.contains(key);
  }
}
