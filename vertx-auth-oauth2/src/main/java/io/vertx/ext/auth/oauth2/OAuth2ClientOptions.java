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
  private static final String KEY_ALGORITHM = "RS256";

  private String authorizationPath;
  private String tokenPath;
  private String revocationPath;
  private String scopeSeparator;
  // this is an openid-connect extension
  private String logoutPath;
  private boolean useBasicAuthorizationHeader;
  private String clientSecretParameterName;
  private String userInfoPath;
  // introspection RFC7662
  private String introspectionPath;

  private String site;
  private String clientID;
  private String clientSecret;
  private String userAgent;
  private JsonObject headers;
  private String publicKey;
  private String privateKey;
  private String keyAlgorithm;
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
    introspectionPath = other.getIntrospectionPath();
    scopeSeparator = other.getScopeSeparator();
    useBasicAuthorizationHeader = other.isUseBasicAuthorizationHeader();
    clientSecretParameterName = other.getClientSecretParameterName();
    // specialization
    site = other.getSite();
    clientID = other.getClientID();
    clientSecret = other.getClientSecret();
    publicKey = other.getPublicKey();
    privateKey = other.getPrivateKey();
    keyAlgorithm = other.getKeyAlgorithm();
    jwtToken = other.isJwtToken();
    logoutPath = other.getLogoutPath();
    // extras
    final JsonObject obj = other.getExtraParameters();
    if (obj != null) {
      extraParams = obj.copy();
    } else {
      extraParams = null;
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
    keyAlgorithm = KEY_ALGORITHM;
    extraParams = null;
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

  public String getAuthorizationPath() {
    return authorizationPath;
  }

  public OAuth2ClientOptions setAuthorizationPath(String authorizationPath) {
    this.authorizationPath = authorizationPath;
    return this;
  }

  public String getTokenPath() {
    return tokenPath;
  }

  public OAuth2ClientOptions setTokenPath(String tokenPath) {
    this.tokenPath = tokenPath;
    return this;
  }

  public String getRevocationPath() {
    return revocationPath;
  }

  public OAuth2ClientOptions setRevocationPath(String revocationPath) {
    this.revocationPath = revocationPath;
    return this;
  }

  public boolean isUseBasicAuthorizationHeader() {
    return useBasicAuthorizationHeader;
  }

  public OAuth2ClientOptions setUseBasicAuthorizationHeader(boolean useBasicAuthorizationHeader) {
    this.useBasicAuthorizationHeader = useBasicAuthorizationHeader;
    return this;
  }

  public String getClientSecretParameterName() {
    return clientSecretParameterName;
  }

  public OAuth2ClientOptions setClientSecretParameterName(String clientSecretParameterName) {
    this.clientSecretParameterName = clientSecretParameterName;
    return this;
  }

  public OAuth2ClientOptions setSite(String site) {
    this.site = site;
    return this;
  }

  public String getClientID() {
    return clientID;
  }

  public OAuth2ClientOptions setClientID(String clientID) {
    this.clientID = clientID;
    return this;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public OAuth2ClientOptions setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
    return this;
  }

  public String getUserAgent() {
    return userAgent;
  }

  public OAuth2ClientOptions setUserAgent(String userAgent) {
    this.userAgent = userAgent;
    return this;
  }

  public JsonObject getHeaders() {
    return headers;
  }

  public OAuth2ClientOptions setHeaders(JsonObject headers) {
    this.headers = headers;
    return this;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public OAuth2ClientOptions setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public OAuth2ClientOptions setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
    return this;
  }

  public String getKeyAlgorithm() {
    return keyAlgorithm;
  }

  public OAuth2ClientOptions setKeyAlgorithm(String keyAlgorithm) {
    this.keyAlgorithm = keyAlgorithm;
    return this;
  }

  public boolean isJwtToken() {
    return jwtToken;
  }

  public OAuth2ClientOptions setJwtToken(boolean jwtToken) {
    this.jwtToken = jwtToken;
    return this;
  }

  public String getLogoutPath() {
    return logoutPath;
  }

  public OAuth2ClientOptions setLogoutPath(String logoutPath) {
    this.logoutPath = logoutPath;
    return this;
  }

  public String getUserInfoPath() {
    return userInfoPath;
  }

  public OAuth2ClientOptions setUserInfoPath(String userInfoPath) {
    this.userInfoPath = userInfoPath;
    return this;
  }

  public String getScopeSeparator() {
    return scopeSeparator;
  }

  public OAuth2ClientOptions setScopeSeparator(String scopeSeparator) {
    this.scopeSeparator = scopeSeparator;
    return this;
  }

  public JsonObject getExtraParameters() {
    return extraParams;
  }

  public OAuth2ClientOptions setExtraParameters(JsonObject extraParams) {
    this.extraParams = extraParams;
    return this;
  }

  public String getIntrospectionPath() {
    return introspectionPath;
  }

  public OAuth2ClientOptions setIntrospectionPath(String introspectionPath) {
    this.introspectionPath = introspectionPath;
    return this;
  }
}
