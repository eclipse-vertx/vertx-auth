package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

/**
 * Options describing Key stored in PEM format.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 * @deprecated instead use {@link io.vertx.ext.auth.jose.PubSecKeyOptions}
 */
@Deprecated
@DataObject
public class PubSecKeyOptions extends io.vertx.ext.auth.jose.PubSecKeyOptions {

  /**
   * Default constructor
   */
  public PubSecKeyOptions() {
    super();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public PubSecKeyOptions(PubSecKeyOptions other) {
    super(other);
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public PubSecKeyOptions(JsonObject json) {
    super(json);
  }

  public PubSecKeyOptions setAlgorithm(String algorithm) {
    return (PubSecKeyOptions) super.setAlgorithm(algorithm);
  }

  public PubSecKeyOptions setBuffer(String buffer) {
    return (PubSecKeyOptions) super.setBuffer(buffer);
  }

  public PubSecKeyOptions setBuffer(Buffer buffer) {
    return (PubSecKeyOptions) super.setBuffer(buffer);
  }

  public PubSecKeyOptions setId(String id) {
    return (PubSecKeyOptions) super.setId(id);
  }

  @Deprecated
  public PubSecKeyOptions setPublicKey(String publicKey) {
    return (PubSecKeyOptions) super.setPublicKey(publicKey);
  }

  @Deprecated
  public PubSecKeyOptions setSecretKey(String secretKey) {
    return (PubSecKeyOptions) super.setSecretKey(secretKey);
  }

  @Deprecated
  public PubSecKeyOptions setSymmetric(boolean symmetric) {
    return (PubSecKeyOptions) super.setSymmetric(symmetric);
  }

  @Deprecated
  public PubSecKeyOptions setCertificate(boolean certificate) {
    return (PubSecKeyOptions) super.setCertificate(certificate);
  }
}
