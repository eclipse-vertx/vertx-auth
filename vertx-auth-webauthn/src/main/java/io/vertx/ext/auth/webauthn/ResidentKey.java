package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;

@VertxGen
public enum ResidentKey {
  DISCOURAGED("discouraged"),
  PREFERRED("preferred"),
  REQUIRED("required");

  private final String value;

  ResidentKey(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return value;
  }

  @Nullable
  @GenIgnore(GenIgnore.PERMITTED_TYPE)
  public static ResidentKey of(String string) {
    for (ResidentKey el : values()) {
      if (el.toString().equals(string)) {
        return el;
      }
    }
    return null;
  }
}
