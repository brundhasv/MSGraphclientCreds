/*
 * (c) Copyright 2022 Hewlett Packard Enterprise Development LP
 *
 * Confidential computer software. Valid license from Hewlett Packard
 * Enterprise required for possession, use or copying.
 *
 * Consistent with FAR 12.211 and 12.212, Commercial Computer Software,
 * Computer Software Documentation, and Technical Data for Commercial Items
 * are licensed to the U.S. Government under vendor's standard commercial
 * license.
 */

package com.msgraph.clientcreds.auth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import com.msgraph.clientcreds.exception.AuthException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class AuthUtil {
    private static final String CERT_TYPE = "X.509";
    private static final String CERT_HASH_ALGO = "SHA-1";
    private static final String PRIVATE_KEY_ALGO = "RSA";

    public static X509Certificate getPublicKeyFromCert(String certFilePath) {
        try (FileInputStream inStream = new FileInputStream(certFilePath)) {
            CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE);
            return (X509Certificate) cf.generateCertificate(inStream);
        } catch (Exception e) {
            throw new AuthException("Error while fetching public key from cert", e.toString());
        }
    }

    public static String getThumbprint(X509Certificate cert) {
        try {
            return Base64.getEncoder().encodeToString(getHash(cert));
        } catch (Exception e) {
            throw new AuthException("Error while fetching thumbprint of cert", e.toString());
        }
    }

    private static byte[] getHash(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        final MessageDigest md = MessageDigest.getInstance(CERT_HASH_ALGO);
        md.update(cert.getEncoded());
        return md.digest();
    }

    public static RSAPrivateKey readPKCS8PrivateKey(String keyFilePath) {
        File file = new File(keyFilePath);
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance(PRIVATE_KEY_ALGO);
        } catch (NoSuchAlgorithmException e) {
            throw new AuthException("Invalid private key algorithm", e.toString());
        }
        try (FileReader keyReader = new FileReader(file, StandardCharsets.UTF_8);
                PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
        } catch (Exception e) {
            throw new AuthException("Error while fetching thumbprint of cert", e.toString());
        }
    }
}
