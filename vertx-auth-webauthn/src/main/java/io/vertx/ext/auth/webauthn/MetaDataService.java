/*
 * Copyright 2019 Red Hat, Inc.
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
package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

/**
 * Factory interface for creating FIDO2 MetaDataService.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface MetaDataService {

  /**
   * Default FIDO2 MDS ROOT Certificate
   */
  String FIDO_MDS_ROOT_CERTIFICATE =
    "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG" +
      "A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk" +
      "YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX" +
      "DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs" +
      "aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS" +
      "b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+" +
      "AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims" +
      "rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw" +
      "DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw" +
      "HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw" +
      "ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW" +
      "DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU" +
      "YjdBz56jSA==";

  /**
   * Fetches the FIDO2 TOC for the given URL and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @param url the url to the TOC
   * @return future result of the operation
   */
  default Future<Boolean> fetchTOC(String url) {
    return fetchTOC(url, FIDO_MDS_ROOT_CERTIFICATE);
  }

  /**
   * Fetches the FIDO2 TOC for the given URL and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @param url the url to the TOC
   * @param handler the async handler to process the response
   * @return fluent self
   */
  @Fluent
  default MetaDataService fetchTOC(String url, Handler<AsyncResult<Boolean>> handler) {
    fetchTOC(url).onComplete(handler);
    return this;
  }

  /**
   * Fetches the FIDO2 TOC for the given URL and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @param url the url to the TOC
   * @param rootCertificate a custom root certificate
   * @param handler the async handler to process the response
   * @return fluent self
   */
  @Fluent
  default MetaDataService fetchTOC(String url, String rootCertificate, Handler<AsyncResult<Boolean>> handler) {
    fetchTOC(url, rootCertificate).onComplete(handler);
    return this;
  }

  /**
   * Fetches the FIDO2 TOC for the given URL and process the entries to the metadata store.
   * Only valid entries will be stored. The operation will return {@code true} only if all
   * entries have been added. {@code false} if they have been processed but at least one was
   * invalid.
   *
   * The operation will only fail on network problems.
   *
   * @param url the url to the TOC
   * @param rootCertificate a custom root certificate
   * @return future result of the operation
   */
  Future<Boolean> fetchTOC(String url, String rootCertificate);

  /**
   * Manually feed a Meta Data Statement to the service.
   *
   * @param statement the json statement
   * @return fluent self
   */
  @Fluent
  MetaDataService addStatement(JsonObject statement);

  /**
   * Clears all loaded statements, both from the TOC and manually inserted.
   * The flush operation will not cancel any in-flight TOC download/processing.
   *
   * @return fluent self
   */
  @Fluent
  MetaDataService flush();
}
