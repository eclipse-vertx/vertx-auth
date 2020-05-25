package io.vertx.ext.auth.htdigest;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

@DataObject(generateConverter = true, publicConverter = false)
public class HtdigestAuthInfo {

  private String algorithm;
  private String cnonce;
  private String method;
  private String nc;
  private String nonce;
  private String qop;
  private String realm;
  private String response;
  private String uri;
  private String username;

  public HtdigestAuthInfo() {
  }

  public HtdigestAuthInfo(JsonObject jsonObject) {
    HtdigestAuthInfoConverter.fromJson(jsonObject, this);
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public String getCnonce() {
    return cnonce;
  }

  public String getMethod() {
    return method;
  }

  public String getNc() {
    return nc;
  }

  public String getNonce() {
    return nonce;
  }

  public String getQop() {
    return qop;
  }

  public String getRealm() {
    return realm;
  }

  public String getResponse() {
    return response;
  }

  public String getUri() {
    return uri;
  }

  public String getUsername() {
    return username;
  }

  public HtdigestAuthInfo setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  public HtdigestAuthInfo setCnonce(String cnonce) {
    this.cnonce = cnonce;
    return this;
  }

  public HtdigestAuthInfo setMethod(String method) {
    this.method = method;
    return this;
  }

  public HtdigestAuthInfo setNc(String nc) {
    this.nc = nc;
    return this;
  }

  public HtdigestAuthInfo setNonce(String nonce) {
    this.nonce = nonce;
    return this;
  }

  public HtdigestAuthInfo setQop(String qop) {
    this.qop = qop;
    return this;
  }

  public HtdigestAuthInfo setRealm(String realm) {
    this.realm = realm;
    return this;
  }

  public HtdigestAuthInfo setResponse(String response) {
    this.response = response;
    return this;
  }

  public HtdigestAuthInfo setUri(String uri) {
    this.uri = uri;
    return this;
  }

  public HtdigestAuthInfo setUsername(String username) {
    this.username = username;
    return this;
  }

  public JsonObject toJson() {
    JsonObject result = new JsonObject();
    HtdigestAuthInfoConverter.toJson(this, result);
    return result;
  }

}
