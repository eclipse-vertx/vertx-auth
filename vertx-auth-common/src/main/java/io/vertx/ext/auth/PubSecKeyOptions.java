package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

/**
 * Options describing Key stored in PEM format.
 * <p>
 * When these options are created from JSON (for example when loading the configuration from a file), the
 * {@code buffer} field is a {@link Buffer}, which in JSON is represented as the <b>base64</b> encoding of the key
 * bytes, <b>not</b> the PEM text itself. Given the PEM (or secret) as a String, the JSON form can be obtained with
 * {@code new PubSecKeyOptions().setBuffer(pem).toJson()}, e.g.:
 * <pre>
 * {
 *   "algorithm": "ES256",
 *   "buffer": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K..."
 * }
 * </pre>
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class PubSecKeyOptions {

  private String algorithm;
  private Buffer buffer;
  private String id;

  /**
   * Default constructor
   */
  public PubSecKeyOptions() {
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public PubSecKeyOptions(PubSecKeyOptions other) {
    algorithm = other.algorithm;
    buffer = other.buffer == null ? null : other.buffer.copy();
    id = other.getId();
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public PubSecKeyOptions(JsonObject json) {
    PubSecKeyOptionsConverter.fromJson(json, this);
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    PubSecKeyOptionsConverter.toJson(this, json);
    return json;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public PubSecKeyOptions setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  /**
   * The PEM or Secret key buffer. When working with secret materials, the material is expected to be encoded in
   * {@code UTF-8}. PEM files are expected to be {@code US_ASCII} as the format uses a base64 encoding for the
   * payload.
   *
   * @return the buffer.
   */
  public Buffer getBuffer() {
    return buffer;
  }

  /**
   * The PEM or Secret key buffer. When working with secret materials, the material is expected to be encoded in
   * {@code UTF-8}. PEM files are expected to be {@code US_ASCII} as the format uses a base64 encoding for the
   * payload.
   * <p>
   * This setter is a convenience for Java code and takes the PEM/secret text as is. In JSON the {@code buffer}
   * field must be the base64 encoding of these bytes, see {@link #setBuffer(Buffer)}.
   *
   * @return self.
   */
  @GenIgnore(GenIgnore.PERMITTED_TYPE)
  public PubSecKeyOptions setBuffer(String buffer) {
    this.buffer = Buffer.buffer(buffer, "UTF-8");
    return this;
  }

  /**
   * The PEM or Secret key buffer. When working with secret materials, the material is expected to be encoded in
   * {@code UTF-8}. PEM files are expected to be {@code US_ASCII} as the format uses a base64 encoding for the
   * payload.
   * <p>
   * This is the setter used when the options are created from JSON: the JSON value of {@code buffer} is the
   * base64 encoding of the key bytes (the standard JSON representation of a {@link Buffer}).
   *
   * @return self.
   */
  public PubSecKeyOptions setBuffer(Buffer buffer) {
    this.buffer = buffer;
    return this;
  }

  public String getId() {
    return id;
  }

  public PubSecKeyOptions setId(String id) {
    this.id = id;
    return this;
  }
}
