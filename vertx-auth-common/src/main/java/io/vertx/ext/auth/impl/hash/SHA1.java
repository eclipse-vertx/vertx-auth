/*
 *  Copyright (c) 2011-2019 The original author or authors
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *       The Eclipse Public License is available at
 *       http://www.eclipse.org/legal/epl-v10.html
 *
 *       The Apache License v2.0 is available at
 *       http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.impl.hash;

/**
 * Implementation of the SHA1 Hashing algorithm
 *
 * @author <a href="mailto:lgao@redhat.com">Lin Gao</a>
 */
public class SHA1 extends AbstractMDHash {

  public SHA1() {
    super("SHA-1");
  }

  @Override
  public String id() { return "sha1"; }

}
