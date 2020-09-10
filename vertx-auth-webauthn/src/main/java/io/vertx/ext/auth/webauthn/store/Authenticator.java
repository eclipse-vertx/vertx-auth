package io.vertx.ext.auth.webauthn.store;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true)
public class Authenticator {

  private String userName;

  private String type = "public-key";
  private String credID;
  private String publicKey;
  private long counter;

  public Authenticator() {}
  public Authenticator(JsonObject json) {
    AuthenticatorConverter.fromJson(json, this);
  }

  public String getUserName() {
    return userName;
  }

  public Authenticator setUserName(String userName) {
    this.userName = userName;
    return this;
  }

  public String getType() {
    return type;
  }

  public Authenticator setType(String type) {
    this.type = type;
    return this;
  }

  public String getCredID() {
    return credID;
  }

  public Authenticator setCredID(String credID) {
    this.credID = credID;
    return this;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public Authenticator setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  public long getCounter() {
    return counter;
  }

  public Authenticator setCounter(long counter) {
    this.counter = counter;
    return this;
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    AuthenticatorConverter.toJson(this, json);
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
