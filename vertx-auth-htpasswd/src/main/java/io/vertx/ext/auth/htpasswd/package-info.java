/*
 * Copyright 2017 Red Hat, Inc.
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

/**
 * == htpasswd Auth Provider implementation
 *
 * We provide an implementation of {@link io.vertx.ext.auth.AuthProvider} which uses the Apache htpasswd file format
 * to perform authentication. The provider will not watch for updates to the file after loading. If you need dynamic
 * user management it would be more convenient to use dynamic providers such as jdbc or mongo providers.
 *
 * To use this project, add the following
 * dependency to the _dependencies_ section of your build descriptor:
 *
 * * Maven (in your `pom.xml`):
 *
 * [source,xml,subs="+attributes"]
 * ----
 * <dependency>
 *   <groupId>${maven.groupId}</groupId>
 *   <artifactId>${maven.artifactId}</artifactId>
 *   <version>${maven.version}</version>
 * </dependency>
 * ----
 *
 * * Gradle (in your `build.gradle` file):
 *
 * [source,groovy,subs="+attributes"]
 * ----
 * compile '${maven.groupId}:${maven.artifactId}:${maven.version}'
 * ----
 *
 * To create an instance you first need an htpasswd file. This file is created using the apache htpasswd tool.
 *
 * Once you've got one of these you can create a {@link io.vertx.ext.auth.htpasswd.HtpasswdAuth} instance as follows:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthHtpasswdExamples#example1(io.vertx.core.Vertx)}
 * ----
 *
 * Once you've got your instance you can authenticate with it just like any {@link io.vertx.ext.auth.AuthProvider}.
 *
 * The out of the box config assumes the usage of the file htpasswd in the root of the project.
 *
 * == Provider internal behavior
 *
 * The provider will load the specified htpasswd file at start time and will not watch for modifications. If you
 * require dynamic reloads, you will need to restart the provider.
 *
 * The implementation does not have any other state than the htpasswd file itself.
 *
 * == Authentication
 *
 * When authenticating using this implementation, it assumes that the username and password are parsed as a JSON
 * object which we refer from now on as authentication info:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthHtpasswdExamples#example2(HtpasswdAuth)}
 * ----
 *
 * == Autorization
 *
 * Apache htpasswd file is a pure authentication mechanism and not authorization but still it is possible to configure
 * default authorization response for all users and for all authorities. It can ether allow or deny all.
 *
 * * Configuration example:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthHtpasswdExamples#example3(io.vertx.core.Vertx)}
 * ----
 *
 * * Authorization checking:
 *
 * [source,$lang]
 * ----
 * {@link examples.AuthHtpasswdExamples#example4}
 * ----
 *
 *
 */
@Document(fileName = "index.adoc")
@ModuleGen(name = "vertx-auth-htpasswd", groupPackage = "io.vertx")
package io.vertx.ext.auth.htpasswd;

import io.vertx.codegen.annotations.ModuleGen;
import io.vertx.docgen.Document;
