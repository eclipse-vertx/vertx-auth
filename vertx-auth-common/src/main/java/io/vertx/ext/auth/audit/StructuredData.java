package io.vertx.ext.auth.audit;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authorization.Authorization;

import java.util.List;
import java.util.Map;

@DataObject
public class StructuredData {

  private final long iat;

  private String sub;
  private String resource;
  private List<Authorization> wants;
  private List<Authorization> has;
  private Map<String, ?> extra;

  public StructuredData() {
    iat = System.currentTimeMillis();
  }

  public StructuredData(Credentials credentials) {
    this(credentials.toJson());
  }

  public StructuredData(JsonObject freeForm) {
    this();
    setSub(freeForm.getString("sub"));
    setResource(freeForm.getString("resource"));
    setExtra(freeForm.getMap());
  }

  public long getIat() {
    return iat;
  }

  public String getSub() {
    return sub;
  }

  public StructuredData setSub(String sub) {
    this.sub = sub;
    return this;
  }

  public String getResource() {
    return resource;
  }

  public StructuredData setResource(String resource) {
    this.resource = resource;
    return this;
  }

  public List<Authorization> getWants() {
    return wants;
  }

  public StructuredData setWants(List<Authorization> wants) {
    this.wants = wants;
    return this;
  }

  public List<Authorization> getHas() {
    return has;
  }

  public StructuredData setHas(List<Authorization> has) {
    this.has = has;
    return this;
  }

  public Map<String, ?> getExtra() {
    return extra;
  }

  public StructuredData setExtra(Map<String, ?> extra) {
    this.extra = extra;
    return this;
  }
}
