package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true)
public class WebAuthNInfo {

  private String challenge;
  private JsonObject webauthn;
  private JsonArray authenticators;

  public WebAuthNInfo() {}

  public WebAuthNInfo(JsonObject json) {
    WebAuthNInfoConverter.fromJson(json, this);
  }

  public String getChallenge() {
    return challenge;
  }

  public WebAuthNInfo setChallenge(String challenge) {
    this.challenge = challenge;
    return this;
  }

  public JsonObject getWebauthn() {
    return webauthn;
  }

  public WebAuthNInfo setWebauthn(JsonObject webauthn) {
    this.webauthn = webauthn;
    return this;
  }

  public JsonArray getAuthenticators() {
    return authenticators;
  }

  public WebAuthNInfo setAuthenticators(JsonArray authenticators) {
    this.authenticators = authenticators;
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    WebAuthNInfoConverter.toJson(this, json);
    // TODO: convert
    return json;
  }
}
