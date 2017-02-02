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

package examples;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;

/**
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class AuthOAuth2Examples {

  public void example1(Vertx vertx) {

    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
            .setClientID("YOUR_CLIENT_ID")
            .setClientSecret("YOUR_CLIENT_SECRET")
            .setSite("https://github.com/login")
            .setTokenPath("/oauth/access_token")
            .setAuthorizationPath("/oauth/authorize")
    );

    // when there is a need to access a protected resource or call a protected method,
    // call the authZ url for a challenge

    String authorization_uri = oauth2.authorizeURL(new JsonObject()
        .put("redirect_uri", "http://localhost:8080/callback")
        .put("scope", "notifications")
        .put("state", "3(#0/!~"));

    // when working with web application use the above string as a redirect url

    // in this case GitHub will call you back in the callback uri one should now complete the handshake as:


    String code = "xxxxxxxxxxxxxxxxxxxxxxxx"; // the code is provided as a url parameter by github callback call

    oauth2.getToken(new JsonObject().put("code", code).put("redirect_uri", "http://localhost:8080/callback"), res -> {
      if (res.failed()) {
        // error, the code provided is not valid
      } else {
        // save the token and continue...
      }
    });
  }

  public void example2(Vertx vertx, HttpServerResponse response) {

    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("<client-id>")
        .setClientSecret("<client-secret>")
        .setSite("https://api.oauth.com");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, credentials);

    // Authorization oauth2 URI
    String authorization_uri = oauth2.authorizeURL(new JsonObject()
        .put("redirect_uri", "http://localhost:8080/callback")
        .put("scope", "<scope>")
        .put("state", "<state>"));

    // Redirect example using Vert.x
    response.putHeader("Location", authorization_uri)
        .setStatusCode(302)
        .end();

    JsonObject tokenConfig = new JsonObject()
        .put("code", "<code>")
        .put("redirect_uri", "http://localhost:3000/callback");

    // Callbacks
    // Save the access token
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        AccessToken token = res.result();
      }
    });
  }

  public void example3(Vertx vertx) {

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.PASSWORD);

    JsonObject tokenConfig = new JsonObject()
        .put("username", "username")
        .put("password", "password");

    // Callbacks
    // Save the access token
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        AccessToken token = res.result();

        oauth2.api(HttpMethod.GET, "/users", new JsonObject().put("access_token", token.principal().getString("access_token")), res2 -> {
          // the user object should be returned here...
        });
      }
    });
  }

  public void example4(Vertx vertx) {

    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("<client-id>")
        .setClientSecret("<client-secret>")
        .setSite("https://api.oauth.com");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, credentials);

    JsonObject tokenConfig = new JsonObject();

    // Callbacks
    // Save the access token
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        AccessToken token = res.result();
      }
    });
  }

  public void example5(AccessToken token) {
    // Check if the token is expired. If expired it is refreshed.
    if (token.expired()) {
      // Callbacks
      token.refresh(res -> {
        if (res.succeeded()) {
          // success
        } else {
          // error handling...
        }
      });
    }
  }

  public void example6(AccessToken token) {
    // Revoke only the access token
    token.revoke("access_token", res -> {
      // Session ended. But the refresh_token is still valid.

      // Revoke the refresh_token
      token.revoke("refresh_token", res1 -> {
        System.out.println("token revoked.");
      });
    });
  }

  public void example13(Vertx vertx) {
    // you would get this config from the keycloak admin console
    JsonObject keycloakJson = new JsonObject()
        .put("realm", "master")
        .put("realm-public-key", "MIIBIjANBgkqhk...wIDAQAB")
        .put("auth-server-url", "http://localhost:9000/auth")
        .put("ssl-required", "external")
        .put("resource", "frontend")
        .put("credentials", new JsonObject()
            .put("secret", "2fbf5e18-b923-4a83-9657-b4ebd5317f60"));

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = KeycloakAuth.create(vertx, OAuth2FlowType.PASSWORD, keycloakJson);

    // first get a token (authenticate)
    oauth2.getToken(new JsonObject().put("username", "user").put("password", "secret"), res -> {
      if (res.failed()) {
        // error handling...
      } else {
        AccessToken token = res.result();

        // now check for permissions
        token.isAuthorised("account:manage-account", r -> {
          if (r.result()) {
            // this user is authorized to manage its account
          }
        });
      }
    });
  }

  public void example14(JsonObject principal) {
    // you can get the decoded `id_token` from the Keycloak principal
    JsonObject idToken = KeycloakHelper.idToken(principal);

    // you can also retrieve some properties directly from the Keycloak principal
    // e.g. `preferred_username`
    String username = KeycloakHelper.preferredUsername(principal);
  }


  public void example15(OAuth2Auth oauth2, AccessToken token) {
    // OAuth2Auth level
    oauth2.introspectToken("opaque string", res -> {
      if (res.succeeded()) {
        // token is valid!
        AccessToken accessToken = res.result();
      }
    });

    // User level
    token.introspect(res -> {
      if (res.succeeded()) {
        // Token is valid!
      }
    });
  }

  public void example16(OAuth2Auth oauth2) {
    // OAuth2Auth level
    oauth2.decodeToken("jwt-token", res -> {
      if (res.succeeded()) {
        // token is valid!
        AccessToken accessToken = res.result();
      }
    });
  }
}
