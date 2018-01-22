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

package io.vertx.ext.auth.mongo.impl;

import io.vertx.core.VertxException;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.HashAlgorithm;
import io.vertx.ext.auth.mongo.HashSaltStyle;
import io.vertx.ext.auth.mongo.HashStrategy;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

/**
 * Implementation of HashStrategy which is using SHA-512 as crypt
 *
 * @author mremme
 */

public class DefaultHashStrategy implements HashStrategy {
  private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
  private static final int WORK_FACTOR = 10000;

  private HashSaltStyle saltStyle;
  // Used only if SaltStyle#External is used
  private String externalSalt;
  // Algorithm
  private HashAlgorithm algorithm;
  private SecretKeyFactory skf;
  private MessageDigest md;

  /**
   *
   */
  public DefaultHashStrategy() {
    saltStyle = HashSaltStyle.COLUMN;
  }

  /**
   * This method is called, if the strategy shall be {@link io.vertx.ext.auth.mongo.HashSaltStyle#EXTERNAL}
   *
   * @param externalSalt the external salt to be used
   */
  public DefaultHashStrategy(String externalSalt) {
    saltStyle = HashSaltStyle.EXTERNAL;
    this.externalSalt = externalSalt;
  }

  private synchronized void initMessageDigest() {
    try {
      if (md == null) {
        md = MessageDigest.getInstance("SHA-512");
      }
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("PBKDF2 is not available", nsae);
    }
  }

  private synchronized void initKeyFactory() {
    try {
      if (skf == null) {
        skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
      }
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("PBKDF2 is not available", nsae);
    }
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.HashStrategy#computeHash(java.lang.String, io.vertx.ext.auth.User)
   */
  @Override
  public String computeHash(String password, User user) {
    switch (saltStyle) {
      case NO_SALT:
        return password;
      case COLUMN:
      case EXTERNAL:
        String salt = getSalt(user);
        return computeHash(password, salt);
      default:
        throw new UnsupportedOperationException("Not existing, saltstyle " + saltStyle);
    }
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.HashStrategy#getStoredPwd(io.vertx.ext.auth.User)
   */
  @Override
  public String getStoredPwd(User user) {
    return ((MongoUser) user).getPassword();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.HashStrategy#getSalt(io.vertx.ext.auth.User)
   */
  @Override
  public String getSalt(User user) {
    switch (saltStyle) {
      case NO_SALT:
        return null;
      case COLUMN:
        return ((MongoUser) user).getSalt();
      case EXTERNAL:
        return externalSalt;
      default:
        throw new UnsupportedOperationException("Not existing, saltstyle " + saltStyle);
    }
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.HashStrategy#setSaltStyle(io.vertx.ext.auth.mongo.HashStrategy.SaltStyle)
   */
  @Override
  public void setSaltStyle(HashSaltStyle saltStyle) {
    this.saltStyle = saltStyle;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.HashStrategy#getSaltStyle()
   */
  @Override
  public HashSaltStyle getSaltStyle() {
    return saltStyle;
  }

  @Override
  public void setAlgorithm(HashAlgorithm algorithm) {
    switch (algorithm) {
      case SHA512:
        initMessageDigest();
        this.algorithm = algorithm;
        break;
      case PBKDF2:
        initKeyFactory();
        this.algorithm = algorithm;
        break;
      default:
        throw new VertxException("Algorithm " + algorithm + " not supported");
    }
  }

  private String computeHash(String password, String salt) {

    // apply defaults
    if (algorithm == null) {
      setAlgorithm(HashAlgorithm.SHA512);
    }

    try {
      switch (algorithm) {
        case SHA512:
          String concat = (salt == null ? "" : salt) + password;
          return bytesToHex(md.digest(concat.getBytes(StandardCharsets.UTF_8)));
        case PBKDF2:
          PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            salt == null ? new byte[]{} : salt.getBytes(StandardCharsets.UTF_8),
            WORK_FACTOR,
            64 * 8);

          return bytesToHex(skf.generateSecret(spec).getEncoded());
        default:
          throw new VertxException("Can't compute hash for algorithm: " + algorithm);
      }
    } catch (InvalidKeySpecException e) {
      throw new VertxException(e);
    }
  }

  /**
   * Generate a salt
   *
   * @return the generated salt
   */
  public static String generateSalt() {
    final Random r = new SecureRandom();
    byte[] salt = new byte[32];
    r.nextBytes(salt);
    return bytesToHex(salt);
  }

  private static String bytesToHex(byte[] bytes) {
    char[] chars = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int x = 0xFF & bytes[i];
      chars[i * 2] = HEX_CHARS[x >>> 4];
      chars[1 + i * 2] = HEX_CHARS[0x0F & x];
    }
    return new String(chars);
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.HashStrategy#setExternalSalt(java.lang.String)
   */
  @Override
  public void setExternalSalt(String externalSalt) {
    this.externalSalt = externalSalt;
  }

}
