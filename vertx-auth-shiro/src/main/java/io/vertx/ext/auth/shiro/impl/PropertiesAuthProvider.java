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

package io.vertx.ext.auth.shiro.impl;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.PropertiesRealm;

import java.io.File;
import java.nio.file.Path;

import static io.vertx.ext.auth.shiro.PropertiesProviderConstants.PROPERTIES_PROPS_PATH_FIELD;

/**
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@Deprecated
public class PropertiesAuthProvider extends ShiroAuthProviderImpl {

  private static String resolve(String resource) {
    if (resource.startsWith("classpath:") || resource.startsWith("url:")) {
      return resource;
    }
    String s = resource;
    if (s.startsWith("file:")) {
      s = s.substring(5);
    }
    String cwd = System.getProperty("vertx.cwd");
    if (cwd != null) {
      Path root = new File(cwd).getAbsoluteFile().toPath().normalize();
      Path path = root.resolve(s);
      if (path.toFile().exists()) {
        resource = path.normalize().toString();
      }
    }
    return resource;
  }

  public static Realm createRealm(JsonObject config) {
    PropertiesRealm propsRealm = new PropertiesRealm();
    String resourcePath = config.getString(PROPERTIES_PROPS_PATH_FIELD);
    if (resourcePath != null) {
      propsRealm.setResourcePath(resolve(resourcePath));
    } else {
      propsRealm.setResourcePath("classpath:vertx-users.properties");
    }
    propsRealm.init();
    return propsRealm;
  }

  public PropertiesAuthProvider(Vertx vertx, Realm realm) {
    super(vertx, realm);
  }
}
