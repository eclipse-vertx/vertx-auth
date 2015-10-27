/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class OAuth2AuthProviderTest extends VertxTestBase {

  protected OAuth2Auth authProvider;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, getConfig());
  }

  protected JsonObject getConfig() {
    return new JsonObject()
        .put("clientID", "CLIENT_ID")
        .put("clientSecret", "CLIENT_SECRET")
        .put("site", "https://github.com/login")
        .put("tokenPath", "/oauth/access_token")
        .put("authorizationPath", "/oauth/authorize");
  }

  @Test
  public void testAuthURI() {
    String authorization_uri = authProvider.authorizeURL(new JsonObject()
        .put("redirect_uri", "http://localhost:8080/callback")
        .put("scope", "notifications")
        .put("state", "3(#0/!~"));

    assertEquals("https://github.com/login/oauth/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=notifications&state=3%28%230%2F%21%7E&response_type=code&client_id=CLIENT_ID", authorization_uri);
  }
}