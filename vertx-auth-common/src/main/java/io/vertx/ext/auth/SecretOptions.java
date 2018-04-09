package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * Options describing a secret.
 *
 * @author <a href="mailto:marco@viafoura.com">Marco Monaco</a>
 */
@Deprecated
@DataObject(generateConverter = true)
public class SecretOptions {
  // Defaults
  private static final String TYPE = "HS256";

  private String type;
  private String secret;

  public SecretOptions() { init(); }

  public SecretOptions(SecretOptions other) {
    type = other.getType();
    secret = other.getSecret();
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public SecretOptions(JsonObject json) {
    init();
    SecretOptionsConverter.fromJson(json, this);
  }

  public String getType() {
    return type;
  }

  public SecretOptions setType(String type) {
    this.type = type;
    return this;
  }

  public String getSecret() {
    return secret;
  }

  public SecretOptions setSecret(String secret) {
    this.secret = secret;
    return this;
  }

  private void init() {
    type = TYPE;
  }
}
