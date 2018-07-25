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
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.ext.auth.oauth2.providers.OpenIDConnectAuth;
import io.vertx.ext.auth.oauth2.rbac.MicroProfileRBAC;

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

    oauth2.authenticate(new JsonObject().put("code", code).put("redirect_uri", "http://localhost:8080/callback"), res -> {
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
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        User token = res.result();
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
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        AccessToken token = (AccessToken) res.result();

        token.fetch("/users", res2 -> {
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
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        User token = res.result();
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
      token.revoke("refresh_token", res1 -> System.out.println("token revoked."));
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
    oauth2.authenticate(new JsonObject().put("username", "user").put("password", "secret"), res -> {
      if (res.failed()) {
        // error handling...
      } else {
        AccessToken token = (AccessToken) res.result();

        // now check for permissions
        token.isAuthorized("account:manage-account", r -> {
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


  public void example17(AccessToken user) {
    user.isAuthorized("print", res -> {
      // in this case it is assumed that the role is the current application
      if (res.succeeded() && res.result()) {
        // Yes the user can print
      }
    });
  }

  public void example18(AccessToken user) {
    user.isAuthorized("realm:add-user", res -> {
      // the role is "realm"
      // the authority is "add-user"
      if (res.succeeded() && res.result()) {
        // Yes the user can add users to the application
      }
    });
  }

  public void example19(AccessToken user) {
    user.isAuthorized("finance:year-report", res -> {
      // the role is "finance"
      // the authority is "year-report"
      if (res.succeeded() && res.result()) {
        // Yes the user can access the year report from the finance department
      }
    });
  }

  public void example20(AccessToken user) {
    user.logout(res -> {
      if (res.succeeded()) {
        // the logout call succeeded
      } else {
        // the user might not have been logged out
        // to know why:
        System.out.println(res.cause());
      }
    });
  }

  public void example21(AccessToken user) {
    // internal validation against, expiration date
    boolean isExpired = user.expired();
  }

  public void example22(AccessToken user) {
    user.refresh(res -> {
      if (res.succeeded()) {
        // the refresh call succeeded
      } else {
        // the token was not refreshed, a best practise would be
        // to forcefully logout the user since this could be a
        // symptom that you're logged out by the server and this
        // token is not valid anymore.
      }
    });
  }

  public void example23(AccessToken user) {
    user.revoke("access_token", res -> {
      if (res.succeeded()) {
        // the refresh call succeeded
      } else {
        // the token was not refreshed, a best practise would be
        // to forcefully logout the user since this could be a
        // symptom that you're logged out by the server and this
        // token is not valid anymore.
      }
    });
  }

  public void example24(AccessToken user) {
    user.introspect(res -> {
      if (res.succeeded()) {
        // the introspection call succeeded
      } else {
        // the token failed the introspection. You should proceed
        // to logout the user since this means that this token is
        // not valid anymore.
      }
    });
  }

  public void example25(Vertx vertx) {

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2ClientOptions()
        .setSite("https://accounts.google.com")
        .setClientID("clientId"),
      res -> {
        if (res.succeeded()) {
          // the setup call succeeded.
          // at this moment your auth is ready to use and
          // google signature keys are loaded so tokens can be decoded and verified.
        } else {
          // the setup failed.
        }
      });
  }

  public void example26(Vertx vertx) {

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2ClientOptions()
        .setSite("http://server:port/auth/realms/your_realm")
        .setClientID("clientId"),
      res -> {
        if (res.succeeded()) {
          // the setup call succeeded.
          // at this moment your auth is ready to use and
          // google signature keys are loaded so tokens can be decoded and verified.
        } else {
          // the setup failed.
        }
      });
  }

  public void example27(OAuth2Auth oauth2Auth) {
    // use the MP-JWT 1.1 spec handler to
    // handle Role-Based Access Control (AuthZ)
    oauth2Auth.rbacHandler(MicroProfileRBAC.create());
  }
}
