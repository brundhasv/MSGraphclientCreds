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
import com.msgraph.clientcreds.model.AuthResponse;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static com.msgraph.clientcreds.auth.AuthJWT.getSignedJWT;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class AuthClient {

    public static AuthResponse fetchNewToken(String tenantId, String type) {
        try {
            TokenRequest request = null;
            if(type.equals("cert")) {
                request = getClientCertTokenRequest(tenantId);
            } else if(type.equals("secret")) {
                request = getClientCredsTokenRequest(tenantId);
            }
            assert request != null;
            TokenResponse response = TokenResponse.parse(request.toHTTPRequest().send());
            if (!response.indicatesSuccess()) {
                TokenErrorResponse errorResponse = response.toErrorResponse();
                Integer errorStatusCode = errorResponse.toHTTPResponse().getStatusCode();
                log.error("Error in Token Response : {}", errorResponse.toHTTPResponse().getBody());
                return new AuthResponse(null, errorStatusCode);
            }
            AccessTokenResponse successResponse = response.toSuccessResponse();
            Integer successStatusCode = successResponse.toHTTPResponse().getStatusCode();
            return new AuthResponse(
                    successResponse.getTokens().getAccessToken().getValue(), successStatusCode);
        } catch (IOException e) {
            throw new AuthException("Error during HTTP Request", e.toString());
        } catch (ParseException e) {
            throw new AuthException("Error during parsing of Token Response", e.toString());
        } catch (URISyntaxException e) {
            throw new AuthException("Token URI Syntax Error", e.toString());
        }
    }

    /** Access token request with a certificate */
    private static TokenRequest getClientCertTokenRequest(String tenantId)
            throws URISyntaxException {
        String tokenUrl = String.format(Constants.MS_APP_TOKEN_URL, tenantId);
        SignedJWT signedJWT = getSignedJWT(tokenUrl);
        ClientAuthentication clientAuth = new PrivateKeyJWT(signedJWT);
        AuthorizationGrant clientGrant = new ClientCredentialsGrant();
        Scope scope = new Scope(Constants.MS_APP_TOKEN_SCOPE);
        URI tokenEndpoint = new URI(tokenUrl);

        // Make the token request
        return new TokenRequest(tokenEndpoint, clientAuth, clientGrant, scope);
    }

    /** Access token request with a secret */
    private static TokenRequest getClientCredsTokenRequest(String tenantId)
            throws URISyntaxException {
        AuthorizationGrant clientGrant = new ClientCredentialsGrant();

        // The credentials to authenticate the client at the token endpoint
        ClientID clientID = new ClientID(Constants.MS_APP_CLIENT_ID);
        Secret clientSecret = new Secret(Constants.MS_APP_CLIENT_SECRET);
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        Scope scope = new Scope(Constants.MS_APP_TOKEN_SCOPE);
        String tokenUrl = String.format(Constants.MS_APP_TOKEN_URL, tenantId);
        URI tokenEndpoint = new URI(tokenUrl);

        // Make the token request
        return new TokenRequest(tokenEndpoint, clientAuth, clientGrant, scope);
    }
}
