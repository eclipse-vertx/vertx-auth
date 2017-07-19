package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

/**
 * Options describing how a Cryptographic Key.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class PubSecKeyOptions {

  // Defaults
  private static final String TYPE = "RSA";

  private String type;
  private String publicKey;
  private String secretKey;

  /**
   * Default constructor
   */
  public PubSecKeyOptions() {
    init();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public PubSecKeyOptions(PubSecKeyOptions other) {
    type = other.getType();
    publicKey = other.getPublicKey();
    secretKey = other.getSecretKey();
  }

  private void init() {
    type = TYPE;
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public PubSecKeyOptions(JsonObject json) {
    init();
    PubSecKeyOptionsConverter.fromJson(json, this);
  }

  public String getType() {
    return type;
  }

  public PubSecKeyOptions setType(String type) {
    this.type = type;
    return this;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public PubSecKeyOptions setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  public String getSecretKey() {
    return secretKey;
  }

  public PubSecKeyOptions setSecretKey(String secretKey) {
    this.secretKey = secretKey;
    return this;
  }
}
