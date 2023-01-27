/*
 * Copyright 2023 Red Hat, Inc.
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
package io.vertx.ext.auth.audit;

import io.vertx.codegen.annotations.VertxGen;

/**
 * A marker will define the structured data id in the log and contains metadata on which fields should be masked.
 * @author Paulo Lopes
 */
@VertxGen
public enum Marker {

  AUTHENTICATION,
  AUTHORIZATION,
  REQUEST;
}
