/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.vertx.sync.ext.auth.jdbc;

import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.sync.AsyncAdaptor;
import co.paralleluniverse.fibers.Suspendable;
/**
 *
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jdbc.JDBCAuth original} non interface using Vert.x codegen.
 */

public class JDBCAuthSync {

  private final JDBCAuth delegate;

  public JDBCAuthSync(JDBCAuth delegate) {
    this.delegate = delegate;
  }

  public JDBCAuth asyncDel() {
    return delegate;
  }

  // The sync methods

}
