/*
 * Copyright (c) 2025 Sanju Thomas
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
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
    return String.format("%s/realms/%s/clients-registrations/default", site, tenant);
  }
}
