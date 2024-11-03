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

import com.msgraph.clientcreds.common.Constants;
import com.msgraph.clientcreds.exception.AuthException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.msgraph.clientcreds.auth.AuthUtil.*;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class AuthJWT {
    private static final String HEADER_ALG = "RS256";
    private static final String HEADER_TYP = "JWT";
    private static final Long JWT_EXPIRY_MINS = 10L;

    private static JWSHeader createJWTHeader() {
        try {
            X509Certificate cert = getPublicKeyFromCert(Constants.CERT_PATH);
            String thumbprint = getThumbprint(cert);
            Map<String, Object> jwsMap = new HashMap<>();
            jwsMap.put("alg", HEADER_ALG);
            jwsMap.put("typ", HEADER_TYP);
            jwsMap.put("x5t", thumbprint);
            JWSHeader jwsHeader = JWSHeader.parse(jwsMap);
            log.debug("JWT header - {}", jwsHeader.toJSONObject());
            return jwsHeader;
        } catch (Exception e) {
            throw new AuthException("Error while creating JWT Header", e.toString());
        }
    }

    private static JWTClaimsSet createJWTClaims(String tokenUrl) {
        LocalDateTime localDate = LocalDateTime.now();
        Date dateNow = Date.from(localDate.atZone(ZoneId.systemDefault()).toInstant());
        LocalDateTime localDateExp = localDate.plus(Duration.ofMinutes(JWT_EXPIRY_MINS));
        Date dateExp = Date.from(localDateExp.atZone(ZoneId.systemDefault()).toInstant());
        UUID uuid = UUID.randomUUID();
        JWTClaimsSet jwtClaims =
                new JWTClaimsSet.Builder()
                        .audience(tokenUrl)
                        .issueTime(dateNow)
                        .notBeforeTime(dateNow)
                        .expirationTime(dateExp)
                        .jwtID(uuid.toString())
                        .issuer(Constants.MS_APP_CLIENT_ID)
                        .subject(Constants.MS_APP_CLIENT_ID)
                        .build();
        log.debug("JWT claims - {}", jwtClaims.getClaims());
        return jwtClaims;
    }

    private static SignedJWT createSignedJWT(String tokenUrl) {
        JWSHeader jwsHeader = createJWTHeader();
        JWTClaimsSet jwtClaims = createJWTClaims(tokenUrl);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaims);
        RSAPrivateKey certJWK = readPKCS8PrivateKey(Constants.CERT_KEY_PATH);
        try {
            signedJWT.sign(new RSASSASigner(certJWK));
        } catch (Exception e) {
            throw new AuthException("Error while signing JWT", e.toString());
        }
        log.debug("JWT Cert Token for MS App - {}", signedJWT.serialize());
        return signedJWT;
    }

    public static SignedJWT getSignedJWT(String tokenUrl) {
        return createSignedJWT(tokenUrl);
    }
}
