/*
 * Copyright 2015 Red Hat, Inc.
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
package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.Vertx;
import io.vertx.core.VertxException;
import io.vertx.core.json.JsonObject;

import java.lang.reflect.Constructor;

/**
 * A common base object for authentication options.<p>
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject
public interface AuthOptions {

  /**
   * Create the auth options from a json value, the implementation makes a lookup on the {@literal provider}
   * property of the json object and returns the corresponding class.
   *
   * @param json the json value
   * @return the auth provider
   */
  static AuthOptions create(JsonObject json) {

    String provider = json.getString("provider", "");
    String impl;
    switch (provider) {
      case "shiro":
        impl = "io.vertx.ext.auth.shiro.ShiroAuthOptions";
        break;
      case "jdbc":
        impl = "io.vertx.ext.auth.jdbc.JDBCAuthOptions";
        break;
      case "mongo":
        impl = "io.vertx.ext.auth.mongo.MongoAuthOptions";
        break;
      default:
        throw new IllegalArgumentException("Invalid auth provider: " + provider);
    }

    try {
      ClassLoader cl = Thread.currentThread().getContextClassLoader();
      Class<?> optionsClass = cl.loadClass(impl);
      Constructor<?> ctor = optionsClass.getConstructor(JsonObject.class);
      return (AuthOptions) ctor.newInstance(json);
    } catch (ClassNotFoundException e) {
      throw new VertxException("Provider class not found " + impl + " / check your classpath");
    } catch(InstantiationException e) {
      throw new VertxException("Cannot create " + provider +" options", e.getCause());
    } catch (Exception e) {
      throw new VertxException("Cannot create " + provider + " options" + provider, e);
    }
  }

  AuthOptions clone();

  /**
   * Create the suitable provider for this option.
   *
   * @param vertx the vertx instance
   * @return the auth provider
   */
  AuthProvider createProvider(Vertx vertx);
}