package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.List;

@DataObject(generateConverter = true)
public class AttestationCertificates {
  private PublicKeyCredential alg;
  private List<String> x5c;
  // by default it is assumed that the x5c includes
  // a root certificate
  private boolean includesRoot = true;

  public AttestationCertificates() {}

  public AttestationCertificates(JsonObject json) {
    AttestationCertificatesConverter.fromJson(json, this);
  }

  public PublicKeyCredential getAlg() {
    return alg;
  }

  public AttestationCertificates setAlg(PublicKeyCredential alg) {
    this.alg = alg;
    return this;
  }

  public List<String> getX5c() {
    return x5c;
  }

  public AttestationCertificates setX5c(JsonArray x5c) {
    if (x5c == null) {
      this.x5c = null;
    } else {
      this.x5c = new ArrayList<>();
      for (int i = 0; i < x5c.size(); i++) {
        this.x5c.add(x5c.getString(i));
      }
    }
    return this;
  }

  public AttestationCertificates setX5c(List<String> x5c) {
    this.x5c = x5c;
    return this;
  }

  public boolean isIncludesRoot() {
    return includesRoot;
  }

  public AttestationCertificates setIncludesRoot(boolean includesRoot) {
    this.includesRoot = includesRoot;
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    AttestationCertificatesConverter.toJson(this, json);
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
