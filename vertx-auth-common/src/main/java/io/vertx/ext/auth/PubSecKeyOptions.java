package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

/**
 * Options describing Key stored in PEM format.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class PubSecKeyOptions {

  private String algorithm;
  private Buffer buffer;
  private String id;

  private boolean certificate;
  private Boolean symmetric;
  private String publicKey;
  private String secretKey;

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
    algorithm = other.getAlgorithm();
    buffer = other.getBuffer();
    id = other.getId();
    publicKey = other.getPublicKey();
    secretKey = other.getSecretKey();
    symmetric = other.isSymmetric();
    certificate = other.isCertificate();
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

  @Deprecated
  public String getPublicKey() {
    return publicKey;
  }

  /**
   * @deprecated This setter ignored the PEM prefix and suffix which would assume the key to be RSA.
   *
   * Use {@link #setBuffer(String)} with the full content of your OpenSSL pem file. A PEM file must
   * contain at least 3 lines:
   *
   * <pre>
   *   -----BEGIN PUBLIC KEY----
   *   ...
   *   -----END PUBLIC KEY---
   * </pre>
   * @param publicKey the naked public key
   * @return self
   */
  @Deprecated
  public PubSecKeyOptions setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  @Deprecated
  public String getSecretKey() {
    return secretKey;
  }

  /**
   * @deprecated This setter ignored the PEM prefix and suffix which would assume the key to be RSA.
   *
   * Use {@link #setBuffer(String)} with the full content of your OpenSSL pem file. A PEM file must
   * contain at least 3 lines:
   *
   * <pre>
   *   -----BEGIN PRIVATE KEY----
   *   ...
   *   -----END PRIVATE KEY---
   * </pre>
   * @param secretKey the naked public key
   * @return self
   */
  @Deprecated
  public PubSecKeyOptions setSecretKey(String secretKey) {
    this.secretKey = secretKey;
    return this;
  }

  @Deprecated
  public boolean isSymmetric() {
    if (symmetric == null) {
      // attempt to derive the kind of key
      return algorithm.startsWith("HS") && publicKey == null && secretKey != null;
    }
    return symmetric;
  }

  @Deprecated
  public PubSecKeyOptions setSymmetric(boolean symmetric) {
    this.symmetric = symmetric;
    return this;
  }

  @Deprecated
  public boolean isCertificate() {
    return certificate;
  }

  @Deprecated
  public PubSecKeyOptions setCertificate(boolean certificate) {
    this.certificate = certificate;
    return this;
  }
}
