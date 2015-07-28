/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.mongo;

/**
 * Password hash salt configuration.
 * <ul>
 * <li>NO_SALT - password hashes are not salted.</li>
 * <li>COLUMN - salt is in a separate column for each user in the database.</li>
 * <li>EXTERNAL - salt is NOT stored in the database, but defined as external value like application preferences or so
 * </li>
 * </ul>
 */
public enum HashSaltStyle {
  NO_SALT, COLUMN, EXTERNAL
}
