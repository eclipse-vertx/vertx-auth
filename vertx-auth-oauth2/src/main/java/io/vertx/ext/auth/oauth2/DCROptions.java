package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;

@DataObject
@JsonGen(publicConverter = false)
public final class DCROptions {

  /**
   * The base url of the OIDC provider like Keycloak.
   */
  private String site;

  /**
   * Name of the tenant if any. Keycloak call this realm.
   */
  private String tenant;

  /**
   * Initial access token to authenticate with the OIDC provider.
   */
  private String initialAccessToken;

  private HttpClientOptions httpClientOptions = new HttpClientOptions();

  public DCROptions(JsonObject json) {
    DCROptionsConverter.fromJson(json, this);
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    DCROptionsConverter.toJson(this, json);
    return json;
  }

  public HttpClientOptions getHttpClientOptions() {
    return httpClientOptions;
  }

  public void setHttpClientOptions(HttpClientOptions httpClientOptions) {
    this.httpClientOptions = httpClientOptions;
  }

  public String getInitialAccessToken() {
    return initialAccessToken;
  }

  public void setInitialAccessToken(String initialAccessToken) {
    this.initialAccessToken = initialAccessToken;
  }

  public String getSite() {
    return site;
  }

  public void setSite(String site) {
    this.site = site;
  }

  public String getTenant() {
    return tenant;
  }

  public void setTenant(String tenant) {
    this.tenant = tenant;
  }

  public String resourceUri() {
    return String.format("%s/%s/%s", site, tenant, "clients-registrations/default/");
  }

}