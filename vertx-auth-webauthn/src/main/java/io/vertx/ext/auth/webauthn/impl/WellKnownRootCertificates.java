package io.vertx.ext.auth.webauthn.impl;

import io.vertx.ext.auth.impl.jose.JWS;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public enum WellKnownRootCertificates {

  // openssl x509 -text -in https://developer.android.com/training/articles/security-key-attestation#root_certificate
  //Certificate:
  //    Data:
  //        Version: 3 (0x2)
  //        Serial Number:
  //            e8:fa:19:63:14:d2:fa:18
  //        Signature Algorithm: sha256WithRSAEncryption
  //        Issuer: serialNumber = f92009e853b6b045
  //        Validity
  //            Not Before: May 26 16:28:52 2016 GMT
  //            Not After : May 24 16:28:52 2026 GMT
  //        Subject: serialNumber = f92009e853b6b045
  //        Subject Public Key Info:
  //            Public Key Algorithm: rsaEncryption
  //                Public-Key: (4096 bit)
  //                Modulus:
  //                    00:af:b6:c7:82:2b:b1:a7:01:ec:2b:b4:2e:8b:cc:
  //                    54:16:63:ab:ef:98:2f:32:c7:7f:75:31:03:0c:97:
  //                    52:4b:1b:5f:e8:09:fb:c7:2a:a9:45:1f:74:3c:bd:
  //                    9a:6f:13:35:74:4a:a5:5e:77:f6:b6:ac:35:35:ee:
  //                    17:c2:5e:63:95:17:dd:9c:92:e6:37:4a:53:cb:fe:
  //                    25:8f:8f:fb:b6:fd:12:93:78:a2:2a:4c:a9:9c:45:
  //                    2d:47:a5:9f:32:01:f4:41:97:ca:1c:cd:7e:76:2f:
  //                    b2:f5:31:51:b6:fe:b2:ff:fd:2b:6f:e4:fe:5b:c6:
  //                    bd:9e:c3:4b:fe:08:23:9d:aa:fc:eb:8e:b5:a8:ed:
  //                    2b:3a:cd:9c:5e:3a:77:90:e1:b5:14:42:79:31:59:
  //                    85:98:11:ad:9e:b2:a9:6b:bd:d7:a5:7c:93:a9:1c:
  //                    41:fc:cd:27:d6:7f:d6:f6:71:aa:0b:81:52:61:ad:
  //                    38:4f:a3:79:44:86:46:04:dd:b3:d8:c4:f9:20:a1:
  //                    9b:16:56:c2:f1:4a:d6:d0:3c:56:ec:06:08:99:04:
  //                    1c:1e:d1:a5:fe:6d:34:40:b5:56:ba:d1:d0:a1:52:
  //                    58:9c:53:e5:5d:37:07:62:f0:12:2e:ef:91:86:1b:
  //                    1b:0e:6c:4c:80:92:74:99:c0:e9:be:c0:b8:3e:3b:
  //                    c1:f9:3c:72:c0:49:60:4b:bd:2f:13:45:e6:2c:3f:
  //                    8e:26:db:ec:06:c9:47:66:f3:c1:28:23:9d:4f:43:
  //                    12:fa:d8:12:38:87:e0:6b:ec:f5:67:58:3b:f8:35:
  //                    5a:81:fe:ea:ba:f9:9a:83:c8:df:3e:2a:32:2a:fc:
  //                    67:2b:f1:20:b1:35:15:8b:68:21:ce:af:30:9b:6e:
  //                    ee:77:f9:88:33:b0:18:da:a1:0e:45:1f:06:a3:74:
  //                    d5:07:81:f3:59:08:29:66:bb:77:8b:93:08:94:26:
  //                    98:e7:4e:0b:cd:24:62:8a:01:c2:cc:03:e5:1f:0b:
  //                    3e:5b:4a:c1:e4:df:9e:af:9f:f6:a4:92:a7:7c:14:
  //                    83:88:28:85:01:5b:42:2c:e6:7b:80:b8:8c:9b:48:
  //                    e1:3b:60:7a:b5:45:c7:23:ff:8c:44:f8:f2:d3:68:
  //                    b9:f6:52:0d:31:14:5e:bf:9e:86:2a:d7:1d:f6:a3:
  //                    bf:d2:45:09:59:d6:53:74:0d:97:a1:2f:36:8b:13:
  //                    ef:66:d5:d0:a5:4a:6e:2f:5d:9a:6f:ef:44:68:32:
  //                    bc:67:84:47:25:86:1f:09:3d:d0:e6:f3:40:5d:a8:
  //                    96:43:ef:0f:4d:69:b6:42:00:51:fd:b9:30:49:67:
  //                    3e:36:95:05:80:d3:cd:f4:fb:d0:8b:c5:84:83:95:
  //                    26:00:63
  //                Exponent: 65537 (0x10001)
  //        X509v3 extensions:
  //            X509v3 Subject Key Identifier:
  //                36:61:E1:00:7C:88:05:09:51:8B:44:6C:47:FF:1A:4C:C9:EA:4F:12
  //            X509v3 Authority Key Identifier:
  //                36:61:E1:00:7C:88:05:09:51:8B:44:6C:47:FF:1A:4C:C9:EA:4F:12
  //            X509v3 Basic Constraints: critical
  //                CA:TRUE
  //            X509v3 Key Usage: critical
  //                Digital Signature, Certificate Sign, CRL Sign
  //            X509v3 CRL Distribution Points:
  //                Full Name:
  //                  URI:https://android.googleapis.com/attestation/crl/
  //    Signature Algorithm: sha256WithRSAEncryption
  //    Signature Value:
  //        20:c8:c3:8d:4b:dc:a9:57:1b:46:8c:89:2f:ff:72:aa:c6:f8:
  //        44:a1:1d:41:a8:f0:73:6c:c3:7d:16:d6:42:6d:8e:7e:94:07:
  //        04:4c:ea:39:e6:8b:07:c1:3d:bf:15:03:dd:5c:85:bd:af:b2:
  //        c0:2d:5f:6c:db:4e:fa:81:27:df:8b:04:f1:82:77:0f:c4:e7:
  //        74:5b:7f:ce:aa:87:12:9a:88:01:ce:8e:9b:c0:cb:96:37:9b:
  //        4d:26:a8:2d:30:fd:9c:2f:8e:ed:6d:c1:be:2f:84:b6:89:e4:
  //        d9:14:25:8b:14:4b:ba:e6:24:a1:c7:06:71:13:2e:2f:06:16:
  //        a8:84:b2:a4:d6:a4:6f:fa:89:b6:02:bf:ba:d8:0c:12:43:71:
  //        1f:56:eb:60:56:f6:37:c8:a0:14:1c:c5:40:94:26:8b:8c:3c:
  //        7d:b9:94:b3:5c:0d:cd:6c:b2:ab:c2:da:fe:e2:52:02:3d:2d:
  //        ea:0c:d6:c3:68:be:a3:e6:41:48:86:f6:b1:e5:8b:5b:d7:c7:
  //        30:b2:68:c4:e3:c1:fb:64:24:b9:1f:eb:bd:b8:0c:58:6e:2a:
  //        e8:36:8c:84:d5:d1:09:17:bd:a2:56:17:89:d4:68:73:93:34:
  //        0e:2e:25:4f:56:0e:f6:4b:23:58:fc:dc:0f:bf:c6:70:09:52:
  //        e7:08:bf:fc:c6:27:50:0c:1f:66:e8:1e:a1:7c:09:8d:7a:2e:
  //        9b:18:80:1b:7a:b4:ac:71:58:7d:34:5d:cc:83:09:d5:b6:2a:
  //        50:42:7a:a6:d0:3d:cb:05:99:6c:96:ba:0c:5d:71:e9:21:62:
  //        c0:16:ca:84:9f:f3:5f:0d:52:c6:5d:05:60:5a:47:f3:ae:91:
  //        7a:cd:2d:f9:10:ef:d2:32:66:88:59:6e:f6:9b:3b:f5:fe:31:
  //        54:f7:ae:b8:80:a0:a7:3c:a0:4d:94:c2:ce:83:17:ee:b4:3d:
  //        5e:ff:58:83:e3:36:f5:f2:49:da:ac:a4:89:92:37:bf:26:7e:
  //        5c:43:ab:02:ea:44:16:24:03:72:3b:e6:aa:69:2c:61:bd:ae:
  //        9e:d4:09:d4:63:c4:c9:7c:64:30:65:77:ee:f2:bc:75:60:b7:
  //        57:15:cc:9c:7d:c6:7c:86:08:2d:b7:51:a8:9c:30:34:97:62:
  //        b0:78:23:85:87:5c:f1:a3:c6:16:6e:0a:e3:c1:2d:37:4e:2d:
  //        4f:18:46:f3:18:74:4b:d8:79:b5:87:32:9b:f0:18:21:7a:6c:
  //        0c:77:24:1a:48:78:e4:35:c0:30:79:cb:45:12:89:c5:77:62:
  //        06:06:9a:2f:8d:65:f8:40:e1:44:52:87:be:d8:77:ab:ae:24:
  //        e2:44:35:16:8d:55:3c:e4
  ANDROID_KEY_1(
    "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"),

  // openssl x509 -text -in https://developer.android.com/training/articles/security-key-attestation#root_certificate
  //Certificate:
  //    Data:
  //        Version: 3 (0x2)
  //        Serial Number:
  //            d5:0f:f2:5b:a3:f2:d6:b3
  //        Signature Algorithm: sha256WithRSAEncryption
  //        Issuer: serialNumber = f92009e853b6b045
  //        Validity
  //            Not Before: Nov 22 20:37:58 2019 GMT
  //            Not After : Nov 18 20:37:58 2034 GMT
  //        Subject: serialNumber = f92009e853b6b045
  //        Subject Public Key Info:
  //            Public Key Algorithm: rsaEncryption
  //                Public-Key: (4096 bit)
  //                Modulus:
  //                    00:af:b6:c7:82:2b:b1:a7:01:ec:2b:b4:2e:8b:cc:
  //                    54:16:63:ab:ef:98:2f:32:c7:7f:75:31:03:0c:97:
  //                    52:4b:1b:5f:e8:09:fb:c7:2a:a9:45:1f:74:3c:bd:
  //                    9a:6f:13:35:74:4a:a5:5e:77:f6:b6:ac:35:35:ee:
  //                    17:c2:5e:63:95:17:dd:9c:92:e6:37:4a:53:cb:fe:
  //                    25:8f:8f:fb:b6:fd:12:93:78:a2:2a:4c:a9:9c:45:
  //                    2d:47:a5:9f:32:01:f4:41:97:ca:1c:cd:7e:76:2f:
  //                    b2:f5:31:51:b6:fe:b2:ff:fd:2b:6f:e4:fe:5b:c6:
  //                    bd:9e:c3:4b:fe:08:23:9d:aa:fc:eb:8e:b5:a8:ed:
  //                    2b:3a:cd:9c:5e:3a:77:90:e1:b5:14:42:79:31:59:
  //                    85:98:11:ad:9e:b2:a9:6b:bd:d7:a5:7c:93:a9:1c:
  //                    41:fc:cd:27:d6:7f:d6:f6:71:aa:0b:81:52:61:ad:
  //                    38:4f:a3:79:44:86:46:04:dd:b3:d8:c4:f9:20:a1:
  //                    9b:16:56:c2:f1:4a:d6:d0:3c:56:ec:06:08:99:04:
  //                    1c:1e:d1:a5:fe:6d:34:40:b5:56:ba:d1:d0:a1:52:
  //                    58:9c:53:e5:5d:37:07:62:f0:12:2e:ef:91:86:1b:
  //                    1b:0e:6c:4c:80:92:74:99:c0:e9:be:c0:b8:3e:3b:
  //                    c1:f9:3c:72:c0:49:60:4b:bd:2f:13:45:e6:2c:3f:
  //                    8e:26:db:ec:06:c9:47:66:f3:c1:28:23:9d:4f:43:
  //                    12:fa:d8:12:38:87:e0:6b:ec:f5:67:58:3b:f8:35:
  //                    5a:81:fe:ea:ba:f9:9a:83:c8:df:3e:2a:32:2a:fc:
  //                    67:2b:f1:20:b1:35:15:8b:68:21:ce:af:30:9b:6e:
  //                    ee:77:f9:88:33:b0:18:da:a1:0e:45:1f:06:a3:74:
  //                    d5:07:81:f3:59:08:29:66:bb:77:8b:93:08:94:26:
  //                    98:e7:4e:0b:cd:24:62:8a:01:c2:cc:03:e5:1f:0b:
  //                    3e:5b:4a:c1:e4:df:9e:af:9f:f6:a4:92:a7:7c:14:
  //                    83:88:28:85:01:5b:42:2c:e6:7b:80:b8:8c:9b:48:
  //                    e1:3b:60:7a:b5:45:c7:23:ff:8c:44:f8:f2:d3:68:
  //                    b9:f6:52:0d:31:14:5e:bf:9e:86:2a:d7:1d:f6:a3:
  //                    bf:d2:45:09:59:d6:53:74:0d:97:a1:2f:36:8b:13:
  //                    ef:66:d5:d0:a5:4a:6e:2f:5d:9a:6f:ef:44:68:32:
  //                    bc:67:84:47:25:86:1f:09:3d:d0:e6:f3:40:5d:a8:
  //                    96:43:ef:0f:4d:69:b6:42:00:51:fd:b9:30:49:67:
  //                    3e:36:95:05:80:d3:cd:f4:fb:d0:8b:c5:84:83:95:
  //                    26:00:63
  //                Exponent: 65537 (0x10001)
  //        X509v3 extensions:
  //            X509v3 Subject Key Identifier:
  //                36:61:E1:00:7C:88:05:09:51:8B:44:6C:47:FF:1A:4C:C9:EA:4F:12
  //            X509v3 Authority Key Identifier:
  //                36:61:E1:00:7C:88:05:09:51:8B:44:6C:47:FF:1A:4C:C9:EA:4F:12
  //            X509v3 Basic Constraints: critical
  //                CA:TRUE
  //            X509v3 Key Usage: critical
  //                Certificate Sign
  //    Signature Algorithm: sha256WithRSAEncryption
  //    Signature Value:
  //        4e:31:a0:5c:f2:8b:a6:5d:bd:af:a1:ce:d7:09:69:ee:5c:a8:
  //        41:04:ad:de:d8:a3:06:cf:7f:6d:ee:50:37:5d:74:5e:d9:92:
  //        cb:02:42:cc:e7:2d:c9:ee:d5:11:91:fe:5a:d5:2b:ad:7d:d3:
  //        b2:5c:09:9e:13:a4:91:a3:cd:d4:87:a5:ac:ce:87:66:32:4c:
  //        4a:e4:63:38:24:6a:e7:b7:8a:41:8a:cb:b9:8a:05:c4:c9:d6:
  //        96:ee:aa:b6:09:d0:ba:0c:e1:a3:1b:e9:84:90:df:3f:4c:0e:
  //        a9:dd:c9:e8:2f:fb:0f:cb:3e:9e:bd:d8:cb:95:27:89:f2:b1:
  //        41:1f:ac:56:c8:86:42:6e:b7:29:60:42:73:5d:a5:0e:11:ac:
  //        71:5f:18:18:cf:9f:dc:4e:25:4a:37:63:35:1b:6a:24:40:15:
  //        08:61:26:3a:6e:31:0b:e1:a5:0d:e5:c7:e8:ee:88:0f:dd:4b:
  //        e5:88:4a:37:12:8d:18:83:0b:b3:47:6b:f4:29:1e:82:d5:c6:
  //        6a:64:94:93:9e:08:48:0b:fb:c0:0f:7d:8a:74:d4:3e:73:73:
  //        7e:be:5d:8e:4e:c5:15:30:2d:46:89:69:27:80:dc:75:38:ed:
  //        7e:91:75:be:61:39:e7:4d:43:ad:38:8b:30:50:ff:d5:a9:de:
  //        52:62:00:08:98:c0:1f:63:c5:3d:fe:22:20:91:08:fa:4f:65:
  //        ba:16:c4:9c:cb:de:08:37:d7:c5:84:4d:54:b7:39:8b:a0:12:
  //        2e:50:5b:15:5c:93:13:cf:e2:6e:72:d8:7e:22:aa:16:16:e6:
  //        bd:bf:54:7d:df:f9:3d:f2:9e:35:a6:3b:45:5f:e1:fc:0e:c9:
  //        55:81:f3:f4:f7:bb:e3:bb:82:83:96:a3:7a:e3:15:75:82:bc:
  //        37:64:b9:78:0a:23:9e:fc:0f:75:a1:e2:e6:d9:41:ce:ab:ac:
  //        27:dd:eb:01:e2:bd:84:21:02:9b:ea:34:d5:1a:ee:6c:60:27:
  //        1d:5a:95:eb:d0:05:15:a9:c0:01:3d:d8:0b:f8:7e:ea:26:0b:
  //        81:c3:4f:68:8e:6e:b1:34:8a:f0:d8:ea:1c:ac:32:ac:b9:d9:
  //        3f:a2:4a:ff:03:0a:84:c8:f2:b0:f5:69:cc:95:08:0b:20:ac:
  //        35:ac:e0:c6:d8:db:d4:f6:84:77:19:51:9d:32:45:01:66:eb:
  //        4b:f1:5b:85:90:44:50:1a:de:af:43:63:82:c3:4b:15:e3:b5:
  //        4c:92:e6:1b:69:c2:bf:c7:26:45:89:17:2b:3c:93:db:e3:5c:
  //        e0:6d:08:fd:5c:01:32:2c:a0:87:7b:1d:12:74:3a:f1:fa:d5:
  //        94:0e:a1:bc:02:dd:89:1c
  ANDROID_KEY_2(
      "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" +
      "ex0SdDrx+tWUDqG8At2JHA=="),

  // openssl x509 -text -in https://developer.android.com/training/articles/security-key-attestation#root_certificate
  //Certificate:
  //    Data:
  //        Version: 3 (0x2)
  //        Serial Number:
  //            c3:6b:7c:44:b9:ae:18:31
  //        Signature Algorithm: sha256WithRSAEncryption
  //        Issuer: serialNumber = f92009e853b6b045
  //        Validity
  //            Not Before: Nov 17 23:10:42 2021 GMT
  //            Not After : Nov 13 23:10:42 2036 GMT
  //        Subject: serialNumber = f92009e853b6b045
  //        Subject Public Key Info:
  //            Public Key Algorithm: rsaEncryption
  //                Public-Key: (4096 bit)
  //                Modulus:
  //                    00:af:b6:c7:82:2b:b1:a7:01:ec:2b:b4:2e:8b:cc:
  //                    54:16:63:ab:ef:98:2f:32:c7:7f:75:31:03:0c:97:
  //                    52:4b:1b:5f:e8:09:fb:c7:2a:a9:45:1f:74:3c:bd:
  //                    9a:6f:13:35:74:4a:a5:5e:77:f6:b6:ac:35:35:ee:
  //                    17:c2:5e:63:95:17:dd:9c:92:e6:37:4a:53:cb:fe:
  //                    25:8f:8f:fb:b6:fd:12:93:78:a2:2a:4c:a9:9c:45:
  //                    2d:47:a5:9f:32:01:f4:41:97:ca:1c:cd:7e:76:2f:
  //                    b2:f5:31:51:b6:fe:b2:ff:fd:2b:6f:e4:fe:5b:c6:
  //                    bd:9e:c3:4b:fe:08:23:9d:aa:fc:eb:8e:b5:a8:ed:
  //                    2b:3a:cd:9c:5e:3a:77:90:e1:b5:14:42:79:31:59:
  //                    85:98:11:ad:9e:b2:a9:6b:bd:d7:a5:7c:93:a9:1c:
  //                    41:fc:cd:27:d6:7f:d6:f6:71:aa:0b:81:52:61:ad:
  //                    38:4f:a3:79:44:86:46:04:dd:b3:d8:c4:f9:20:a1:
  //                    9b:16:56:c2:f1:4a:d6:d0:3c:56:ec:06:08:99:04:
  //                    1c:1e:d1:a5:fe:6d:34:40:b5:56:ba:d1:d0:a1:52:
  //                    58:9c:53:e5:5d:37:07:62:f0:12:2e:ef:91:86:1b:
  //                    1b:0e:6c:4c:80:92:74:99:c0:e9:be:c0:b8:3e:3b:
  //                    c1:f9:3c:72:c0:49:60:4b:bd:2f:13:45:e6:2c:3f:
  //                    8e:26:db:ec:06:c9:47:66:f3:c1:28:23:9d:4f:43:
  //                    12:fa:d8:12:38:87:e0:6b:ec:f5:67:58:3b:f8:35:
  //                    5a:81:fe:ea:ba:f9:9a:83:c8:df:3e:2a:32:2a:fc:
  //                    67:2b:f1:20:b1:35:15:8b:68:21:ce:af:30:9b:6e:
  //                    ee:77:f9:88:33:b0:18:da:a1:0e:45:1f:06:a3:74:
  //                    d5:07:81:f3:59:08:29:66:bb:77:8b:93:08:94:26:
  //                    98:e7:4e:0b:cd:24:62:8a:01:c2:cc:03:e5:1f:0b:
  //                    3e:5b:4a:c1:e4:df:9e:af:9f:f6:a4:92:a7:7c:14:
  //                    83:88:28:85:01:5b:42:2c:e6:7b:80:b8:8c:9b:48:
  //                    e1:3b:60:7a:b5:45:c7:23:ff:8c:44:f8:f2:d3:68:
  //                    b9:f6:52:0d:31:14:5e:bf:9e:86:2a:d7:1d:f6:a3:
  //                    bf:d2:45:09:59:d6:53:74:0d:97:a1:2f:36:8b:13:
  //                    ef:66:d5:d0:a5:4a:6e:2f:5d:9a:6f:ef:44:68:32:
  //                    bc:67:84:47:25:86:1f:09:3d:d0:e6:f3:40:5d:a8:
  //                    96:43:ef:0f:4d:69:b6:42:00:51:fd:b9:30:49:67:
  //                    3e:36:95:05:80:d3:cd:f4:fb:d0:8b:c5:84:83:95:
  //                    26:00:63
  //                Exponent: 65537 (0x10001)
  //        X509v3 extensions:
  //            X509v3 Subject Key Identifier:
  //                36:61:E1:00:7C:88:05:09:51:8B:44:6C:47:FF:1A:4C:C9:EA:4F:12
  //            X509v3 Authority Key Identifier:
  //                36:61:E1:00:7C:88:05:09:51:8B:44:6C:47:FF:1A:4C:C9:EA:4F:12
  //            X509v3 Basic Constraints: critical
  //                CA:TRUE
  //            X509v3 Key Usage: critical
  //                Certificate Sign
  //    Signature Algorithm: sha256WithRSAEncryption
  //    Signature Value:
  //        53:34:d6:5e:e5:cb:9f:f2:88:aa:fa:35:74:8a:d4:c6:cd:65:
  //        61:49:38:ce:04:49:36:15:0b:e1:d7:52:77:a3:79:67:6b:4a:
  //        3b:ad:df:11:14:79:cd:d3:4a:b8:86:2e:93:6a:91:61:87:8a:
  //        9a:c3:f8:86:e9:78:3e:c4:e6:a7:eb:79:e2:2d:62:02:e4:63:
  //        8f:16:03:de:61:73:3d:fa:70:5b:df:36:73:0b:c0:01:ca:96:
  //        2e:0a:eb:16:0a:6b:7a:4e:7d:fe:3e:36:f3:dc:c4:d5:85:11:
  //        97:b9:3f:d3:40:7e:0a:18:56:38:3e:1b:f3:03:25:f0:76:34:
  //        ce:09:72:03:f9:a1:ee:77:84:4b:71:2c:92:af:41:6a:fc:bf:
  //        91:f1:35:9a:96:f3:35:c0:92:4f:87:24:63:a9:10:89:7a:b1:
  //        ad:7c:16:a0:88:02:f3:be:19:e6:63:b5:35:a8:57:12:d0:d0:
  //        a7:2a:3a:0e:ee:81:5e:74:a7:56:95:9c:f4:60:07:ee:dd:a1:
  //        82:25:de:0a:1d:3d:0c:b0:68:8b:65:ec:fd:58:ff:35:c5:84:
  //        ab:28:c3:44:b0:32:be:cc:ae:5f:57:3c:3a:8c:0e:dc:c6:6a:
  //        57:70:04:53:9e:60:2e:19:47:88:ed:55:43:84:3c:ca:79:53:
  //        9c:b5:fd:da:d2:a4:0b:c0:2f:9d:d3:ec:6b:11:36:78:af:67:
  //        d1:18:dc:36:60:4b:36:5b:c4:23:ea:80:dc:7c:fb:ea:f4:9c:
  //        92:7b:ba:49:eb:07:07:9e:5e:44:67:49:70:73:8c:47:ed:8e:
  //        03:c7:d4:40:d4:99:5f:a2:82:cc:c3:7b:4e:74:96:47:d1:e9:
  //        f1:3d:76:b2:75:f0:03:dd:88:9f:79:9a:45:69:4c:e2:70:77:
  //        8b:cd:52:4b:b7:d7:6f:18:1d:1b:1d:02:c4:e3:e1:2a:28:58:
  //        0e:66:fd:84:a0:fe:bc:e8:34:2a:6d:54:b5:bb:ef:64:d2:9d:
  //        b1:6c:c0:35:d3:94:c1:22:4e:e7:a6:b6:9a:f1:53:34:7e:7a:
  //        d1:2a:2e:f0:95:92:b0:74:7f:9a:34:0c:a1:6d:74:56:f7:1b:
  //        27:38:32:7e:83:c7:85:e3:9d:b3:bd:b8:8a:2a:78:04:2a:2a:
  //        ca:e4:b1:a2:7a:85:c1:5f:bb:59:f4:3d:46:34:11:f6:39:bd:
  //        db:28:ec:30:21:67:44:16:57:bf:60:5f:e1:eb:35:a0:75:ea:
  //        1a:34:60:ea:54:1a:cb:af:6f:b4:0e:d5:a8:88:1d:5a:0c:48:
  //        cb:5a:5f:45:9b:22:14:c9:49:bb:98:3f:ef:14:39:33:17:ec:
  //        26:ed:cc:96:a5:0a:42:55
  ANDROID_KEY_3(
      "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" +
      "mD/vFDkzF+wm7cyWpQpCVQ=="),

  // openssl x509 -text -in https://pki.goog/roots.pem
  //Certificate:
  //    Data:
  //        Version: 3 (0x2)
  //        Serial Number:
  //            04:00:00:00:00:01:15:4b:5a:c3:94
  //        Signature Algorithm: sha1WithRSAEncryption
  //        Issuer: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
  //        Validity
  //            Not Before: Sep  1 12:00:00 1998 GMT
  //            Not After : Jan 28 12:00:00 2028 GMT
  //        Subject: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
  //        Subject Public Key Info:
  //            Public Key Algorithm: rsaEncryption
  //                Public-Key: (2048 bit)
  //                Modulus:
  //                    00:da:0e:e6:99:8d:ce:a3:e3:4f:8a:7e:fb:f1:8b:
  //                    83:25:6b:ea:48:1f:f1:2a:b0:b9:95:11:04:bd:f0:
  //                    63:d1:e2:67:66:cf:1c:dd:cf:1b:48:2b:ee:8d:89:
  //                    8e:9a:af:29:80:65:ab:e9:c7:2d:12:cb:ab:1c:4c:
  //                    70:07:a1:3d:0a:30:cd:15:8d:4f:f8:dd:d4:8c:50:
  //                    15:1c:ef:50:ee:c4:2e:f7:fc:e9:52:f2:91:7d:e0:
  //                    6d:d5:35:30:8e:5e:43:73:f2:41:e9:d5:6a:e3:b2:
  //                    89:3a:56:39:38:6f:06:3c:88:69:5b:2a:4d:c5:a7:
  //                    54:b8:6c:89:cc:9b:f9:3c:ca:e5:fd:89:f5:12:3c:
  //                    92:78:96:d6:dc:74:6e:93:44:61:d1:8d:c7:46:b2:
  //                    75:0e:86:e8:19:8a:d5:6d:6c:d5:78:16:95:a2:e9:
  //                    c8:0a:38:eb:f2:24:13:4f:73:54:93:13:85:3a:1b:
  //                    bc:1e:34:b5:8b:05:8c:b9:77:8b:b1:db:1f:20:91:
  //                    ab:09:53:6e:90:ce:7b:37:74:b9:70:47:91:22:51:
  //                    63:16:79:ae:b1:ae:41:26:08:c8:19:2b:d1:46:aa:
  //                    48:d6:64:2a:d7:83:34:ff:2c:2a:c1:6c:19:43:4a:
  //                    07:85:e7:d3:7c:f6:21:68:ef:ea:f2:52:9f:7f:93:
  //                    90:cf
  //                Exponent: 65537 (0x10001)
  //        X509v3 extensions:
  //            X509v3 Key Usage: critical
  //                Certificate Sign, CRL Sign
  //            X509v3 Basic Constraints: critical
  //                CA:TRUE
  //            X509v3 Subject Key Identifier:
  //                60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B
  //    Signature Algorithm: sha1WithRSAEncryption
  //    Signature Value:
  //        d6:73:e7:7c:4f:76:d0:8d:bf:ec:ba:a2:be:34:c5:28:32:b5:
  //        7c:fc:6c:9c:2c:2b:bd:09:9e:53:bf:6b:5e:aa:11:48:b6:e5:
  //        08:a3:b3:ca:3d:61:4d:d3:46:09:b3:3e:c3:a0:e3:63:55:1b:
  //        f2:ba:ef:ad:39:e1:43:b9:38:a3:e6:2f:8a:26:3b:ef:a0:50:
  //        56:f9:c6:0a:fd:38:cd:c4:0b:70:51:94:97:98:04:df:c3:5f:
  //        94:d5:15:c9:14:41:9c:c4:5d:75:64:15:0d:ff:55:30:ec:86:
  //        8f:ff:0d:ef:2c:b9:63:46:f6:aa:fc:df:bc:69:fd:2e:12:48:
  //        64:9a:e0:95:f0:a6:ef:29:8f:01:b1:15:b5:0c:1d:a5:fe:69:
  //        2c:69:24:78:1e:b3:a7:1c:71:62:ee:ca:c8:97:ac:17:5d:8a:
  //        c2:f8:47:86:6e:2a:c4:56:31:95:d0:67:89:85:2b:f9:6c:a6:
  //        5d:46:9d:0c:aa:82:e4:99:51:dd:70:b7:db:56:3d:61:e4:6a:
  //        e1:5c:d6:f6:fe:3d:de:41:cc:07:ae:63:52:bf:53:53:f4:2b:
  //        e9:c7:fd:b6:f7:82:5f:85:d2:41:18:db:81:b3:04:1c:c5:1f:
  //        a4:80:6f:15:20:c9:de:0c:88:0a:1d:d6:66:55:e2:fc:48:c9:
  //        29:26:69:e0
  ANDROID_SAFETYNET(
      "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG" +
      "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv" +
      "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw" +
      "MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i" +
      "YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT" +
      "aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ" +
      "jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp" +
      "xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp" +
      "1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG" +
      "snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ" +
      "U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8" +
      "9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E" +
      "BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B" +
      "AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz" +
      "yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE" +
      "38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP" +
      "AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad" +
      "DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME" +
      "HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A=="),

  // openssl x509 -text -in https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
  //Certificate:
  //    Data:
  //        Version: 3 (0x2)
  //        Serial Number:
  //            68:1d:01:6c:7a:3c:e3:02:25:a5:01:94:28:47:57:71
  //        Signature Algorithm: ecdsa-with-SHA384
  //        Issuer: CN = Apple WebAuthn Root CA, O = Apple Inc., ST = California
  //        Validity
  //            Not Before: Mar 18 18:21:32 2020 GMT
  //            Not After : Mar 15 00:00:00 2045 GMT
  //        Subject: CN = Apple WebAuthn Root CA, O = Apple Inc., ST = California
  //        Subject Public Key Info:
  //            Public Key Algorithm: id-ecPublicKey
  //                Public-Key: (384 bit)
  //                pub:
  //                    04:22:42:43:6a:53:56:1c:e3:97:85:a8:e8:88:47:
  //                    b4:c4:80:cc:ed:9c:bf:e1:fd:0d:02:9e:bf:7f:ff:
  //                    7c:6e:7d:1b:5d:64:c6:ef:5e:23:4f:fb:a3:a5:79:
  //                    b9:28:41:a5:ed:6e:ea:5e:a6:4b:5f:52:d4:51:21:
  //                    eb:21:a5:8e:76:40:27:ed:86:34:fd:66:8b:f6:0a:
  //                    da:44:97:22:e4:c7:8f:10:3f:a5:ca:11:7f:b5:e4:
  //                    3a:d3:b8:a3:5a:a5:71
  //                ASN1 OID: secp384r1
  //                NIST CURVE: P-384
  //        X509v3 extensions:
  //            X509v3 Basic Constraints: critical
  //                CA:TRUE
  //            X509v3 Subject Key Identifier:
  //                26:D7:64:D9:C5:78:C2:5A:67:D1:A7:DE:6B:12:D0:1B:63:F1:C6:D7
  //            X509v3 Key Usage: critical
  //                Certificate Sign, CRL Sign
  //    Signature Algorithm: ecdsa-with-SHA384
  //    Signature Value:
  //        30:64:02:30:5a:d9:fb:d0:ec:27:53:d6:f6:17:cd:74:1c:b0:
  //        64:3b:16:0d:b5:85:a7:6f:22:b7:57:7f:e7:0d:91:3e:44:57:
  //        dc:16:e7:fd:46:c3:4c:d2:f1:ec:9a:f7:8c:01:86:89:02:30:
  //        1c:58:fe:74:96:58:50:94:7b:f3:aa:2c:07:20:5e:94:96:2c:
  //        55:97:76:19:b1:d0:bb:6d:3d:6f:94:42:98:64:36:d6:0a:52:
  //        02:4f:50:65:6e:01:d5:b5:9e:4f:4b:d3
  APPLE(
      "MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w" +
      "HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ" +
      "bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx" +
      "NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG" +
      "A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49" +
      "AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k" +
      "xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/" +
      "pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk" +
      "2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA" +
      "MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3" +
      "jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B" +
      "1bWeT0vT"),

  // openssl x509 -text -in https://valid.r3.roots.globalsign.com/
  //Certificate:
  //    Data:
  //        Version: 3 (0x2)
  //        Serial Number:
  //            04:00:00:00:00:01:21:58:53:08:a2
  //        Signature Algorithm: sha256WithRSAEncryption
  //        Issuer: OU = GlobalSign Root CA - R3, O = GlobalSign, CN = GlobalSign
  //        Validity
  //            Not Before: Mar 18 10:00:00 2009 GMT
  //            Not After : Mar 18 10:00:00 2029 GMT
  //        Subject: OU = GlobalSign Root CA - R3, O = GlobalSign, CN = GlobalSign
  //        Subject Public Key Info:
  //            Public Key Algorithm: rsaEncryption
  //                Public-Key: (2048 bit)
  //                Modulus:
  //                    00:cc:25:76:90:79:06:78:22:16:f5:c0:83:b6:84:
  //                    ca:28:9e:fd:05:76:11:c5:ad:88:72:fc:46:02:43:
  //                    c7:b2:8a:9d:04:5f:24:cb:2e:4b:e1:60:82:46:e1:
  //                    52:ab:0c:81:47:70:6c:dd:64:d1:eb:f5:2c:a3:0f:
  //                    82:3d:0c:2b:ae:97:d7:b6:14:86:10:79:bb:3b:13:
  //                    80:77:8c:08:e1:49:d2:6a:62:2f:1f:5e:fa:96:68:
  //                    df:89:27:95:38:9f:06:d7:3e:c9:cb:26:59:0d:73:
  //                    de:b0:c8:e9:26:0e:83:15:c6:ef:5b:8b:d2:04:60:
  //                    ca:49:a6:28:f6:69:3b:f6:cb:c8:28:91:e5:9d:8a:
  //                    61:57:37:ac:74:14:dc:74:e0:3a:ee:72:2f:2e:9c:
  //                    fb:d0:bb:bf:f5:3d:00:e1:06:33:e8:82:2b:ae:53:
  //                    a6:3a:16:73:8c:dd:41:0e:20:3a:c0:b4:a7:a1:e9:
  //                    b2:4f:90:2e:32:60:e9:57:cb:b9:04:92:68:68:e5:
  //                    38:26:60:75:b2:9f:77:ff:91:14:ef:ae:20:49:fc:
  //                    ad:40:15:48:d1:02:31:61:19:5e:b8:97:ef:ad:77:
  //                    b7:64:9a:7a:bf:5f:c1:13:ef:9b:62:fb:0d:6c:e0:
  //                    54:69:16:a9:03:da:6e:e9:83:93:71:76:c6:69:85:
  //                    82:17
  //                Exponent: 65537 (0x10001)
  //        X509v3 extensions:
  //            X509v3 Key Usage: critical
  //                Certificate Sign, CRL Sign
  //            X509v3 Basic Constraints: critical
  //                CA:TRUE
  //            X509v3 Subject Key Identifier:
  //                8F:F0:4B:7F:A8:2E:45:24:AE:4D:50:FA:63:9A:8B:DE:E2:DD:1B:BC
  //    Signature Algorithm: sha256WithRSAEncryption
  //    Signature Value:
  //        4b:40:db:c0:50:aa:fe:c8:0c:ef:f7:96:54:45:49:bb:96:00:
  //        09:41:ac:b3:13:86:86:28:07:33:ca:6b:e6:74:b9:ba:00:2d:
  //        ae:a4:0a:d3:f5:f1:f1:0f:8a:bf:73:67:4a:83:c7:44:7b:78:
  //        e0:af:6e:6c:6f:03:29:8e:33:39:45:c3:8e:e4:b9:57:6c:aa:
  //        fc:12:96:ec:53:c6:2d:e4:24:6c:b9:94:63:fb:dc:53:68:67:
  //        56:3e:83:b8:cf:35:21:c3:c9:68:fe:ce:da:c2:53:aa:cc:90:
  //        8a:e9:f0:5d:46:8c:95:dd:7a:58:28:1a:2f:1d:de:cd:00:37:
  //        41:8f:ed:44:6d:d7:53:28:97:7e:f3:67:04:1e:15:d7:8a:96:
  //        b4:d3:de:4c:27:a4:4c:1b:73:73:76:f4:17:99:c2:1f:7a:0e:
  //        e3:2d:08:ad:0a:1c:2c:ff:3c:ab:55:0e:0f:91:7e:36:eb:c3:
  //        57:49:be:e1:2e:2d:7c:60:8b:c3:41:51:13:23:9d:ce:f7:32:
  //        6b:94:01:a8:99:e7:2c:33:1f:3a:3b:25:d2:86:40:ce:3b:2c:
  //        86:78:c9:61:2f:14:ba:ee:db:55:6f:df:84:ee:05:09:4d:bd:
  //        28:d8:72:ce:d3:62:50:65:1e:eb:92:97:83:31:d9:b3:b5:ca:
  //        47:58:3f:5f
  MDS(
      "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G" +
      "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp" +
      "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4" +
      "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG" +
      "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI" +
      "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8" +
      "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT" +
      "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm" +
      "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd" +
      "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ" +
      "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw" +
      "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o" +
      "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU" +
      "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp" +
      "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK" +
      "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX" +
      "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs" +
      "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH" +
      "WD9f");

  private final String x509text;

  WellKnownRootCertificates(String x509text) {
    this.x509text = x509text;
  }

  public X509Certificate certificate() throws CertificateException {
    X509Certificate cert = JWS.parseX5c(x509text);
    cert.checkValidity();
    return cert;
  }
}
