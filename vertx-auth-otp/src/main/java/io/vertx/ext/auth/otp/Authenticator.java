package io.vertx.ext.auth.otp;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true)
public class Authenticator {

  private String identifier;
  private String key;
  private String algorithm;

  private long counter;
  private Integer authAttempts;

  boolean registration;

  public Authenticator(boolean registration) {
    this.registration = registration;
  }

  public Authenticator() {}

  public Authenticator(JsonObject json) {
    AuthenticatorConverter.fromJson(json, this);
  }

  public String getIdentifier() {
    return identifier;
  }

  public Authenticator setIdentifier(String identifier) {
    this.identifier = identifier;
    return this;
  }

  public String getKey() {
    return key;
  }

  public Authenticator setKey(String key) {
    this.key = key;
    return this;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public Authenticator setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  public long getCounter() {
    return counter;
  }

  public Authenticator setCounter(long counter) {
    this.counter = counter;
    return this;
  }

  public Integer getAuthAttempts() {
    return authAttempts;
  }

  public Authenticator setAuthAttempts(Integer authAttempts) {
    this.authAttempts = authAttempts;
    return this;
  }

  @GenIgnore
  public boolean isRegistration() {
    return registration;
  }

  @GenIgnore
  public Authenticator registered() {
    registration = false;
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    AuthenticatorConverter.toJson(this, json);
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
