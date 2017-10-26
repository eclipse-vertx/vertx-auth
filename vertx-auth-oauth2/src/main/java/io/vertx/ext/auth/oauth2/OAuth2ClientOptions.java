/*
 * Copyright (c) 2011-2014 The original author or authors
 * ------------------------------------------------------
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 *     The Eclipse Public License is available at
 *     http://www.eclipse.org/legal/epl-v10.html
 *
 *     The Apache License v2.0 is available at
 *     http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;

/**
 * Options describing how an OAuth2 {@link HttpClient} will make connections.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class OAuth2ClientOptions extends HttpClientOptions {

  // Defaults
  private static final String AUTHORIZATION_PATH = "/oauth/authorize";
  private static final String TOKEN_PATH = "/oauth/token";
  private static final String REVOKATION_PATH = "/oauth/revoke";
  private static final boolean USE_BASIC_AUTHORIZATION_HEADER = true;
  private static final String CLIENT_SECRET_PARAMETER_NAME = "client_secret";
  private static final boolean JWT_TOKEN = false;
  private static final String SCOPE_SEPARATOR = " ";

  private String authorizationPath;
  private String tokenPath;
  private String revocationPath;
  private String scopeSeparator;
  // this is an openid-connect extension
  private String logoutPath;
  private boolean useBasicAuthorizationHeader;
  private String clientSecretParameterName;
  private String userInfoPath;
  // extra parameters to be added while requesting the user info
  private JsonObject userInfoParams;
  // introspection RFC7662
  private String introspectionPath;
  // JWK path RFC7517
  private String jwkPath;
  private long keyRefreshInterval;

  private String site;
  private String clientID;
  private String clientSecret;
  private String userAgent;
  private JsonObject headers;
  private PubSecKeyOptions pubSecKey;
  private boolean jwtToken;
  // extra parameters to be added while requesting a token
  private JsonObject extraParams;

  public String getSite() {
    return site;
  }

  /**
   * Default constructor
   */
  public OAuth2ClientOptions() {
    super();
    init();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public OAuth2ClientOptions(HttpClientOptions other) {
    super(other);
    init();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public OAuth2ClientOptions(OAuth2ClientOptions other) {
    super(other);
    // defaults
    authorizationPath = other.getAuthorizationPath();
    tokenPath = other.getTokenPath();
    revocationPath = other.getRevocationPath();
    userInfoPath = other.getUserInfoPath();
    introspectionPath = other.getIntrospectionPath();
    scopeSeparator = other.getScopeSeparator();
    useBasicAuthorizationHeader = other.isUseBasicAuthorizationHeader();
    clientSecretParameterName = other.getClientSecretParameterName();
    // specialization
    site = other.getSite();
    clientID = other.getClientID();
    clientSecret = other.getClientSecret();
    pubSecKey = other.getPubSecKey();
    jwtToken = other.isJwtToken();
    logoutPath = other.getLogoutPath();
    // extras
    final JsonObject obj = other.getExtraParameters();
    if (obj != null) {
      extraParams = obj.copy();
    } else {
      extraParams = null;
    }
    // user info params
    final JsonObject obj2 = other.getUserInfoParameters();
    if (obj2 != null) {
      userInfoParams = obj2.copy();
    } else {
      userInfoParams = null;
    }
    // custom headers
    final JsonObject obj3 = other.getHeaders();
    if (obj3 != null) {
      headers = obj3.copy();
    } else {
      headers = null;
    }
  }

  private void init() {
    authorizationPath = AUTHORIZATION_PATH;
    tokenPath = TOKEN_PATH;
    revocationPath = REVOKATION_PATH;
    scopeSeparator = SCOPE_SEPARATOR;
    useBasicAuthorizationHeader = USE_BASIC_AUTHORIZATION_HEADER;
    clientSecretParameterName = CLIENT_SECRET_PARAMETER_NAME;
    jwtToken = JWT_TOKEN;
    extraParams = null;
    userInfoParams = null;
    headers = null;
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public OAuth2ClientOptions(JsonObject json) {
    super(json);
    init();
    OAuth2ClientOptionsConverter.fromJson(json, this);
  }

  /**
   * Get the Oauth2 authorization resource path. e.g.: /oauth/authorize
   * @return authorization path
   */
  public String getAuthorizationPath() {
    return authorizationPath;
  }

  public OAuth2ClientOptions setAuthorizationPath(String authorizationPath) {
    this.authorizationPath = authorizationPath;
    return this;
  }

  /**
   * Get the Oauth2 token resource path. e.g.: /oauth/token
   * @return token path
   */
  public String getTokenPath() {
    return tokenPath;
  }

  public OAuth2ClientOptions setTokenPath(String tokenPath) {
    this.tokenPath = tokenPath;
    return this;
  }

  /**
   * Get the Oauth2 revocation resource path. e.g.: /oauth/revoke
   * @return revocation path
   */
  public String getRevocationPath() {
    return revocationPath;
  }

  /**
   * Set the Oauth2 revocation resource path. e.g.: /oauth/revoke
   * @return self
   */
  public OAuth2ClientOptions setRevocationPath(String revocationPath) {
    this.revocationPath = revocationPath;
    return this;
  }

  /**
   * Flag to use HTTP basic auth header with client id, client secret.
   *
   * @return boolean
   */
  public boolean isUseBasicAuthorizationHeader() {
    return useBasicAuthorizationHeader;
  }

  /**
   * Flag to use HTTP basic auth header with client id, client secret.
   *
   * @return self
   */
  public OAuth2ClientOptions setUseBasicAuthorizationHeader(boolean useBasicAuthorizationHeader) {
    this.useBasicAuthorizationHeader = useBasicAuthorizationHeader;
    return this;
  }

  /**
   * When a provider uses a non standard HTTP form field name, the client secret can be overriden here.
   *
   * @return the provider form field name
   */
  public String getClientSecretParameterName() {
    return clientSecretParameterName;
  }

  /**
   * Override the HTTP form field name for client secret
   *
   * @param clientSecretParameterName the new nme
   * @return self
   */
  public OAuth2ClientOptions setClientSecretParameterName(String clientSecretParameterName) {
    this.clientSecretParameterName = clientSecretParameterName;
    return this;
  }

  /**
   * Root URL for the provider
   * @param site a url
   * @return self
   */
  public OAuth2ClientOptions setSite(String site) {
    this.site = site;
    return this;
  }

  /**
   * Get the provider client id
   * @return client id
   */
  public String getClientID() {
    return clientID;
  }

  /**
   * Set the provider client id
   * @param clientID client id
   * @return self
   */
  public OAuth2ClientOptions setClientID(String clientID) {
    this.clientID = clientID;
    return this;
  }

  /**
   * Get the provider client secret
   * @return the client secret
   */
  public String getClientSecret() {
    return clientSecret;
  }

  /**
   * Set the provider client secret
   * @param clientSecret client secret
   * @return self
   */
  public OAuth2ClientOptions setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
    return this;
  }

  /**
   * The User-Agent header to use when communicating with a provider
   * @return the user agent string
   */
  public String getUserAgent() {
    return userAgent;
  }

  /**
   * Set a custom user agent to use when communicating to a provider
   * @param userAgent the user agent
   * @return self
   */
  public OAuth2ClientOptions setUserAgent(String userAgent) {
    this.userAgent = userAgent;
    return this;
  }

  /**
   * Custom headers to send along with every request.
   * @return the headers as a json structure
   */
  public JsonObject getHeaders() {
    return headers;
  }

  /**
   * Set custom headers to be sent with every request to the provider
   * @param headers the headers
   * @return self
   */
  public OAuth2ClientOptions setHeaders(JsonObject headers) {
    this.headers = headers;
    return this;
  }

  /**
   * The provider PubSec key options
   * @return the pub sec key options
   */
  public PubSecKeyOptions getPubSecKey() {
    return pubSecKey;
  }

  public OAuth2ClientOptions setPubSecKeyOptions(PubSecKeyOptions pubSecKey) {
    this.pubSecKey = pubSecKey;
    return this;
  }

  /**
   * Flag if this provider returns tokens in JWT format
   * @return boolean
   */
  public boolean isJwtToken() {
    return jwtToken;
  }

  /**
   * Signal that this provider tokens are in JWT format
   * @param jwtToken true or false
   * @return self
   */
  public OAuth2ClientOptions setJwtToken(boolean jwtToken) {
    this.jwtToken = jwtToken;
    return this;
  }

  /**
   * The provider logout path
   * @return a logout resource path
   */
  public String getLogoutPath() {
    return logoutPath;
  }

  /**
   * Set the provider logout path
   * @param logoutPath a logout resource path
   * @return self
   */
  public OAuth2ClientOptions setLogoutPath(String logoutPath) {
    this.logoutPath = logoutPath;
    return this;
  }

  /**
   * The provider userInfo resource path
   * @return a resouce path
   */
  public String getUserInfoPath() {
    return userInfoPath;
  }

  /**
   * Set the provider userInfo resource path
   * @param userInfoPath a resource path
   * @return self
   */
  public OAuth2ClientOptions setUserInfoPath(String userInfoPath) {
    this.userInfoPath = userInfoPath;
    return this;
  }

  /**
   * Set the provider scope separator
   * @return a single character string usually a space or a plus
   */
  public String getScopeSeparator() {
    return scopeSeparator;
  }

  /**
   * Set the provider scope separator
   * @param scopeSeparator a separator e.g.: ' ', '+', ','
   * @return self
   */
  public OAuth2ClientOptions setScopeSeparator(String scopeSeparator) {
    this.scopeSeparator = scopeSeparator;
    return this;
  }

  /**
   * Extra parameters to send to the provider
   * @return a json representation of the parameters
   */
  public JsonObject getExtraParameters() {
    return extraParams;
  }

  /**
   * Set extra parameters to be sent to the provider on each request
   * @param extraParams a json representation of the parameters
   * @return self
   */
  public OAuth2ClientOptions setExtraParameters(JsonObject extraParams) {
    this.extraParams = extraParams;
    return this;
  }

  /**
   * The provider token introspection resource path
   * @return the resource path
   */
  public String getIntrospectionPath() {
    return introspectionPath;
  }

  /**
   * Set the provider token introspection resource path
   * @param introspectionPath a resource path
   * @return self
   */
  public OAuth2ClientOptions setIntrospectionPath(String introspectionPath) {
    this.introspectionPath = introspectionPath;
    return this;
  }

  /**
   * Set the provider custom userInfo parameters to send when requesting them.
   * @return a json representation of the extra parameters
   */
  public JsonObject getUserInfoParameters() {
    return userInfoParams;
  }

  /**
   * Set custom parameters to be sent during the userInfo resource request
   * @param userInfoParams json representation of the parameters
   * @return self
   */
  public OAuth2ClientOptions setUserInfoParameters(JsonObject userInfoParams) {
    this.userInfoParams = userInfoParams;
    return this;
  }
}
