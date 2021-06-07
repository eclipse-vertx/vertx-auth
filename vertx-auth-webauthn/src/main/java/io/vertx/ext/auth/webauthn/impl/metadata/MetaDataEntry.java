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
package io.vertx.ext.auth.webauthn.impl.metadata;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.Shareable;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class MetaDataEntry implements Shareable {

  private static final Logger LOG = LoggerFactory.getLogger(MetaDataEntry.class);

  private static final Base64.Decoder BASE64DEC = Base64.getDecoder();
  // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
  private static final List<String> INVALID_STATUS = Arrays
    .asList(
      "USER_VERIFICATION_BYPASS",
      "ATTESTATION_KEY_COMPROMISE",
      "USER_KEY_REMOTE_COMPROMISE",
      "USER_KEY_PHYSICAL_COMPROMISE",
      "REVOKED");
  private static final List<String> INFO_STATUS = Arrays
    .asList(
      "UPDATE_AVAILABLE"
    );

  private final int version;
  private final JsonObject entry;
  private final JsonObject statement;
  private final String error;

  public MetaDataEntry(JsonObject statement) {
    if (statement == null) {
      throw new IllegalArgumentException("MetaData statement cannot be null");
    }
    this.entry = null;
    this.statement = statement;
    this.error = null;
    this.version = statement.getInteger("schema", 2);
  }

  public MetaDataEntry(JsonObject tocEntry, JsonObject statement, String error) throws NoSuchAlgorithmException {
    if (tocEntry == null || statement == null) {
      throw new IllegalArgumentException("toc and statement cannot be null");
    }

    this.entry = tocEntry;
    this.error = error;
    this.statement = statement;
    this.version = statement.getInteger("schema", 2);

    // convert status report effective date to a Instant
    for (Object o : entry.getJsonArray("statusReports")) {
      JsonObject statusReport = (JsonObject) o;
      statusReport.put(
        "effectiveDate",
        LocalDate.parse(statusReport.getString("effectiveDate"), DateTimeFormatter.ISO_DATE).atStartOfDay().toInstant(ZoneOffset.UTC));
    }
  }

  public MetaDataEntry(JsonObject tocEntry, byte[] rawStatement, String error) throws NoSuchAlgorithmException {
    if (tocEntry == null || rawStatement == null) {
      throw new IllegalArgumentException("toc and statement cannot be null");
    }

    this.entry = tocEntry;
    this.statement = new JsonObject(Buffer.buffer(BASE64DEC.decode(rawStatement)));
    this.version = statement.getInteger("schema", 2);

    // convert status report effective date to a Instant
    for (Object o : entry.getJsonArray("statusReports")) {
      JsonObject statusReport = (JsonObject) o;
      statusReport.put(
        "effectiveDate",
        LocalDate.parse(statusReport.getString("effectiveDate"), DateTimeFormatter.ISO_DATE).atStartOfDay().toInstant(ZoneOffset.UTC));
    }

    if (error != null) {
      this.error = error;
    } else {
      // verify the hash
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      byte[] digest = sha256.digest(rawStatement);
      if (MessageDigest.isEqual(digest, entry.getBinary("hash"))) {
        this.error = null;
      } else {
        this.error = "MDS entry hash did not match corresponding hash in MDS TOC";
      }
    }
  }

  void checkValid() throws MetaDataException {

    if (error != null) {
      throw new MetaDataException(error);
    }

    if (entry != null) {
      final Instant now = Instant.now();
      // look up the status reports, backwards
      JsonArray reports = entry.getJsonArray("statusReports");

      for (int i = reports.size() - 1; i >= 0; i--) {
        JsonObject statusReport = reports.getJsonObject(i);
        if (statusReport.getInstant("effectiveDate").isBefore(now)) {
          if (INFO_STATUS.contains(statusReport.getString("status"))) {
            LOG.info("Software Update is available: " + statement.getString("description"));
          }
          if (INVALID_STATUS.contains(statusReport.getString("status"))) {
            throw new MetaDataException("Invalid MDS status: " + statusReport.getString("status"));
          }
          return;
        }
      }
      // no status was found for the current date
      throw new MetaDataException("Invalid MDS statusReports");
    }
  }

  JsonObject statement() {
    return statement;
  }
}
