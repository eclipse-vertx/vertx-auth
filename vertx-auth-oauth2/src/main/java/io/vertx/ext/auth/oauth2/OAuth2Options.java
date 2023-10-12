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
import io.vertx.codegen.annotations.Fluent;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Options describing how an OAuth2 {@link HttpClient} will make connections.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class OAuth2Options {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2Options.class);

  // Defaults
  private static final boolean BASIC_AUTHORIZATION = true;
  private static final String AUTHORIZATION_PATH = "/oauth/authorize";
  private static final String TOKEN_PATH = "/oauth/token";
  private static final String REVOCATION_PATH = "/oauth/revoke";
  private static final String SCOPE_SEPARATOR = " ";
  private static final boolean VALIDATE_ISSUER = true;
  //seconds of JWK's default age (-1 means no rotation)
  private static final long JWK_DEFAULT_AGE = -1L;

  private List<String> supportedGrantTypes;
  private String authorizationPath;
  private String tokenPath;
  private String revocationPath;
  private String scopeSeparator;
  // this is an openid-connect extension
  private boolean validateIssuer;
  private String logoutPath;
  private String userInfoPath;
  // extra parameters to be added while requesting the user info
  private JsonObject userInfoParams;
  // introspection RFC7662
  private String introspectionPath;
  // JWK path RFC7517
  private String jwkPath;
  //seconds of JWKs lifetime
  private long jwkMaxAge;
  // OpenID non standard
  private String tenant;

  private String site;
  private String clientId;
  private String clientSecret;

  private boolean useBasicAuthorization;

  //https://tools.ietf.org/html/rfc7521
  private String clientAssertionType;
  private String clientAssertion;

  private String userAgent;
  private JsonObject headers;
  private List<PubSecKeyOptions> pubSecKeys;
  private JWTOptions jwtOptions;
  // extra parameters to be added while requesting a token
  private JsonObject extraParams;
  // client config
  private HttpClientOptions httpClientOptions = new HttpClientOptions();
  private List<JsonObject> jwks;

  public String getSite() {
    return site;
  }

  /**
   * Default constructor
   */
  public OAuth2Options() {
    init();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public OAuth2Options(OAuth2Options other) {
    tenant = other.getTenant();
    clientId = other.getClientId();
    clientSecret = other.getClientSecret();
    useBasicAuthorization = other.isUseBasicAuthorization();
    clientAssertionType = other.getClientAssertionType();
    clientAssertion = other.getClientAssertion();
    validateIssuer = other.isValidateIssuer();
    authorizationPath = other.getAuthorizationPath();
    tokenPath = other.getTokenPath();
    revocationPath = other.getRevocationPath();
    userInfoPath = other.getUserInfoPath();
    introspectionPath = other.getIntrospectionPath();
    scopeSeparator = other.getScopeSeparator();
    site = other.getSite();
    pubSecKeys = other.getPubSecKeys();
    jwtOptions = other.getJWTOptions();
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
    jwkPath = other.getJwkPath();
    jwkMaxAge = other.getJwkMaxAgeInSeconds();
    httpClientOptions = other.getHttpClientOptions();
    userAgent = other.getUserAgent();
    supportedGrantTypes = other.getSupportedGrantTypes();
    final List<JsonObject> jwks = other.getJwks();
    if (jwks != null) {
      this.jwks = new ArrayList<>(jwks);
    } else {
      this.jwks = null;
    }
    // compute paths with variables, at this moment it is only relevant that
    // the paths and site are properly computed
    replaceVariables(false);
  }

  private void init() {
    validateIssuer = VALIDATE_ISSUER;
    authorizationPath = AUTHORIZATION_PATH;
    tokenPath = TOKEN_PATH;
    revocationPath = REVOCATION_PATH;
    scopeSeparator = SCOPE_SEPARATOR;
    jwtOptions = new JWTOptions();;
    jwkMaxAge = JWK_DEFAULT_AGE;
    useBasicAuthorization = BASIC_AUTHORIZATION;
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public OAuth2Options(JsonObject json) {
    init();
    OAuth2OptionsConverter.fromJson(json, this);
    // compute paths with variables, at this moment it is only relevant that
    // the paths and site are properly computed
    replaceVariables(false);
  }

  /**
   * Get the Oauth2 authorization resource path. e.g.: /oauth/authorize
   *
   * @return authorization path
   */
  public String getAuthorizationPath() {
    return authorizationPath;
  }

  public OAuth2Options setAuthorizationPath(String authorizationPath) {
    this.authorizationPath = authorizationPath;
    return this;
  }

  /**
   * Get the Oauth2 token resource path. e.g.: /oauth/token
   *
   * @return token path
   */
  public String getTokenPath() {
    return tokenPath;
  }

  public OAuth2Options setTokenPath(String tokenPath) {
    this.tokenPath = tokenPath;
    return this;
  }

  /**
   * Get the Oauth2 revocation resource path. e.g.: /oauth/revoke
   *
   * @return revocation path
   */
  public String getRevocationPath() {
    return revocationPath;
  }

  /**
   * Set the Oauth2 revocation resource path. e.g.: /oauth/revoke
   *
   * @return self
   */
  public OAuth2Options setRevocationPath(String revocationPath) {
    this.revocationPath = revocationPath;
    return this;
  }

  /**
   * Root URL for the provider without trailing slashes
   *
   * @param site a url
   * @return self
   */
  public OAuth2Options setSite(String site) {
    this.site = site;
    return this;
  }

  /**
   * Get the provider client id
   *
   * @return client id
   */
  public String getClientId() {
    return clientId;
  }

  /**
   * Set the provider client id
   *
   * @param clientId client id
   * @return self
   */
  public OAuth2Options setClientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  /**
   * Get the provider client secret
   *
   * @return the client secret
   */
  public String getClientSecret() {
    return clientSecret;
  }

  /**
   * Set the provider client secret
   *
   * @param clientSecret client secret
   * @return self
   */
  public OAuth2Options setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
    return this;
  }

  public OAuth2Options setUseBasicAuthorization(boolean useBasicAuthorization) {
    this.useBasicAuthorization = useBasicAuthorization;
    return this;
  }

  public boolean isUseBasicAuthorization() {
    return useBasicAuthorization;
  }

  public String getClientAssertionType() {
    return clientAssertionType;
  }

  public OAuth2Options setClientAssertionType(String clientAssertionType) {
    this.clientAssertionType = clientAssertionType;
    return this;
  }

  public String getClientAssertion() {
    return clientAssertion;
  }

  public OAuth2Options setClientAssertion(String clientAssertion) {
    this.clientAssertion = clientAssertion;
    return this;
  }

  /**
   * The User-Agent header to use when communicating with a provider
   *
   * @return the user agent string
   */
  public String getUserAgent() {
    return userAgent;
  }

  /**
   * Set a custom user agent to use when communicating to a provider
   *
   * @param userAgent the user agent
   * @return self
   */
  public OAuth2Options setUserAgent(String userAgent) {
    this.userAgent = userAgent;
    return this;
  }

  /**
   * Custom headers to send along with every request.
   *
   * @return the headers as a json structure
   */
  public JsonObject getHeaders() {
    return headers;
  }

  /**
   * Set custom headers to be sent with every request to the provider
   *
   * @param headers the headers
   * @return self
   */
  public OAuth2Options setHeaders(JsonObject headers) {
    this.headers = headers;
    return this;
  }

  /**
   * The provider PubSec key options
   *
   * @return the pub sec key options
   */
  public List<PubSecKeyOptions> getPubSecKeys() {
    return pubSecKeys;
  }

  public OAuth2Options setPubSecKeys(List<PubSecKeyOptions> pubSecKeys) {
    this.pubSecKeys = pubSecKeys;
    return this;
  }

  public OAuth2Options addPubSecKey(PubSecKeyOptions pubSecKey) {
    if (pubSecKeys == null) {
      pubSecKeys = new ArrayList<>();
    }
    pubSecKeys.add(pubSecKey);
    return this;
  }

  /**
   * The provider logout path
   *
   * @return a logout resource path
   */
  public String getLogoutPath() {
    return logoutPath;
  }

  /**
   * Set the provider logout path
   *
   * @param logoutPath a logout resource path
   * @return self
   */
  public OAuth2Options setLogoutPath(String logoutPath) {
    this.logoutPath = logoutPath;
    return this;
  }

  /**
   * The provider userInfo resource path
   *
   * @return a resouce path
   */
  public String getUserInfoPath() {
    return userInfoPath;
  }

  /**
   * Set the provider userInfo resource path
   *
   * @param userInfoPath a resource path
   * @return self
   */
  public OAuth2Options setUserInfoPath(String userInfoPath) {
    this.userInfoPath = userInfoPath;
    return this;
  }

  /**
   * Set the provider scope separator
   *
   * @return a single character string usually a space or a plus
   */
  public String getScopeSeparator() {
    return scopeSeparator;
  }

  /**
   * Set the provider scope separator
   *
   * @param scopeSeparator a separator e.g.: ' ', '+', ','
   * @return self
   */
  public OAuth2Options setScopeSeparator(String scopeSeparator) {
    this.scopeSeparator = scopeSeparator;
    return this;
  }

  /**
   * Extra parameters to send to the provider
   *
   * @return a json representation of the parameters
   */
  public JsonObject getExtraParameters() {
    return extraParams;
  }

  /**
   * Set extra parameters to be sent to the provider on each request
   *
   * @param extraParams a json representation of the parameters
   * @return self
   */
  public OAuth2Options setExtraParameters(JsonObject extraParams) {
    this.extraParams = extraParams;
    return this;
  }

  /**
   * The provider token introspection resource path
   *
   * @return the resource path
   */
  public String getIntrospectionPath() {
    return introspectionPath;
  }

  /**
   * Set the provider token introspection resource path
   *
   * @param introspectionPath a resource path
   * @return self
   */
  public OAuth2Options setIntrospectionPath(String introspectionPath) {
    this.introspectionPath = introspectionPath;
    return this;
  }

  /**
   * Set the provider custom userInfo parameters to send when requesting them.
   *
   * @return a json representation of the extra parameters
   */
  public JsonObject getUserInfoParameters() {
    return userInfoParams;
  }

  /**
   * Set custom parameters to be sent during the userInfo resource request
   *
   * @param userInfoParams json representation of the parameters
   * @return self
   */
  public OAuth2Options setUserInfoParameters(JsonObject userInfoParams) {
    this.userInfoParams = userInfoParams;
    return this;
  }

  public String getJwkPath() {
    return jwkPath;
  }

  public OAuth2Options setJwkPath(String jwkPath) {
    this.jwkPath = jwkPath;
    return this;
  }

  public JWTOptions getJWTOptions() {
    return jwtOptions;
  }

  public OAuth2Options setJWTOptions(JWTOptions jwtOptions) {
    this.jwtOptions = jwtOptions;
    return this;
  }

  public boolean isValidateIssuer() {
    return validateIssuer;
  }

  public OAuth2Options setValidateIssuer(boolean validateIssuer) {
    this.validateIssuer = validateIssuer;
    return this;
  }

  public String getTenant() {
    return tenant;
  }

  /**
   * Sets an optional tenant. Tenants are used in some OpenID servers as placeholders for the URLs.
   * The tenant should be set prior to any URL as it affects the way the URLs will be stored.
   * <p>
   * Some provders may name this differently, for example: `realm`.
   *
   * @param tenant the tenant/realm for this config.
   * @return self
   */
  public OAuth2Options setTenant(String tenant) {
    this.tenant = tenant;
    return this;
  }

  /**
   * The provider supported grant types
   *
   * @return the supported grant types options
   */
  public List<String> getSupportedGrantTypes() {
    return supportedGrantTypes;
  }

  public OAuth2Options setSupportedGrantTypes(List<String> supportedGrantTypes) {
    this.supportedGrantTypes = supportedGrantTypes;
    return this;
  }

  public OAuth2Options addSupportedGrantType(String supportedGrantType) {
    if (supportedGrantTypes == null) {
      supportedGrantTypes = new ArrayList<>();
    }
    supportedGrantTypes.add(supportedGrantType);
    return this;
  }


  public void replaceVariables(boolean strict) {
    // strip trailing slashes if present
    if (site != null && site.endsWith("/")) {
      site = site.substring(0, site.length() - 1);
    }

    site = replaceVariables(site);

    authorizationPath = replaceVariables(authorizationPath);
    tokenPath = replaceVariables(tokenPath);
    revocationPath = replaceVariables(revocationPath);
    logoutPath = replaceVariables(logoutPath);
    userInfoPath = replaceVariables(userInfoPath);
    introspectionPath = replaceVariables(introspectionPath);
    jwkPath = replaceVariables(jwkPath);

    if (extraParams != null) {
      for (Map.Entry<String, Object> kv : extraParams) {
        Object v = kv.getValue();
        if (v instanceof String) {
          try {
            kv.setValue(replaceVariables((String) v));
          } catch (IllegalStateException e) {
            // if we're strict the we assert that even the optional extra parameters must
            // be updated with the variable value
            if (strict) {
              throw e;
            }
          }
        }
      }
    }
  }

  private static final Pattern TENANT_PATTER = Pattern.compile("\\{(tenant|realm)}");

  private String replaceVariables(String path) {
    if (path != null) {
      final Matcher matcher = TENANT_PATTER.matcher(path);
      if (matcher.find()) {
        if (tenant == null) {
          throw new IllegalStateException("Configuration with placeholders require that \"tenant\" is prior set");
        }

        return matcher.replaceAll(tenant);
      }
    }

    return path;
  }

  public void validate() throws IllegalStateException {
    List<String> supportedGrantTypes = getSupportedGrantTypes();
    if (supportedGrantTypes == null) {
      // we default to AUTH_CODE and IMPLICIT as defined in the OpenID Connect spec
      supportedGrantTypes = Arrays.asList(OAuth2FlowType.AUTH_CODE.getGrantType(), OAuth2FlowType.IMPLICIT.getGrantType());
    }
    for (OAuth2FlowType flow : OAuth2FlowType.values()) {
      if (!supportedGrantTypes.contains(flow.getGrantType())) {
        continue;
      }
      switch (flow) {
        case AUTH_CODE:
        case AUTH_JWT:
        case AAD_OBO:
          if (clientAssertion == null && clientAssertionType == null) {
            // not using client assertions
            if (clientId == null) {
              throw new IllegalStateException("Configuration missing. You need to specify [clientId]");
            }
          } else {
            if (clientAssertion == null || clientAssertionType == null) {
              throw new IllegalStateException(
                "Configuration missing. You need to specify [clientAssertion] AND [clientAssertionType]");
            }
          }
          break;
        case PASSWORD:
          if (clientAssertion == null && clientAssertionType == null) {
            // not using client assertions
            if (clientId == null) {
              LOG.debug("If you are using Client Oauth2 Resource Owner flow. You need to specify [clientId]");
            }
          } else {
            if (clientAssertion == null || clientAssertionType == null) {
              throw new IllegalStateException(
                "Configuration missing. You need to specify [clientAssertion] AND [clientAssertionType]");
            }
          }
          break;
      }
    }
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    OAuth2OptionsConverter.toJson(this, json);
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  public HttpClientOptions getHttpClientOptions() {
    return httpClientOptions;
  }

  public OAuth2Options setHttpClientOptions(HttpClientOptions httpClientOptions) {
    this.httpClientOptions = httpClientOptions;
    return this;
  }

  public long getJwkMaxAgeInSeconds() {
    return jwkMaxAge;
  }

  /**
   * -1 means no rotation for JWKs
   *
   * @param jwkMaxAgeInSeconds timeout of JWKs rotation
   */
  public void setJwkMaxAgeInSeconds(long jwkMaxAgeInSeconds) {
    this.jwkMaxAge = jwkMaxAgeInSeconds;
  }

  public List<JsonObject> getJwks() {
    return jwks;
  }

  /**
   * Sets the initial local JWKs
   * @param jwks a json array as defined in https://tools.ietf.org/html/rfc7517#section-5
   * @return self
   */
  @Fluent
  public OAuth2Options setJwks(List<JsonObject> jwks) {
    this.jwks = jwks;
    return this;
  }

  /**
   * Adds a local JWKs
   * @param jwk a single keyas defined in https://tools.ietf.org/html/rfc7517#section-5
   * @return self
   */
  @Fluent
  public OAuth2Options addJwk(JsonObject jwk) {
    if (this.jwks == null) {
      this.jwks = new ArrayList<>();
    }

    this.jwks.add(jwk);
    return this;
  }
}
