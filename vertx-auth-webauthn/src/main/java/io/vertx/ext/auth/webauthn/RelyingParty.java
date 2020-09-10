package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true)
public class RelyingParty {
  private String id;
  private String name;
  private String icon;

  public RelyingParty() {
  }

  public RelyingParty(JsonObject json) {
    RelyingPartyConverter.fromJson(json, this);
  }

  public RelyingParty(RelyingParty other) {
    this.id = other.id;
    this.name = other.name;
    this.icon = other.icon;
  }

  public String getId() {
    return id;
  }

  public RelyingParty setId(String id) {
    this.id = id;
    return this;
  }

  public String getName() {
    return name;
  }

  public RelyingParty setName(String name) {
    this.name = name;
    return this;
  }

  public String getIcon() {
    return icon;
  }

  public RelyingParty setIcon(String icon) {
    this.icon = icon;
    return this;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    RelyingPartyConverter.toJson(this, json);
    return json;
  }
}
