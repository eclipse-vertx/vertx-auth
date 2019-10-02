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
package io.vertx.ext.auth.htpasswd.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;
import org.apache.commons.codec.digest.Md5Crypt;

/**
 * Implementation of the APR1 Hashing algorithm
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class APR1 implements HashingAlgorithm {

  @Override
  public String id() {
    return "apr1";
  }

  @Override
  public String hash(HashString hashString, String password) {
    final String apr1Salt = "$apr1$" + hashString.salt();
    String res = Md5Crypt.apr1Crypt(password, apr1Salt);
    // we need to exclude the salt part
    return res.substring(apr1Salt.length() + 1);
  }
}
