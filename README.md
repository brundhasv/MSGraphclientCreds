# MS Graph API Certificate and Client Secret OAuth2.0 in Java Spring boot

## Overview

Microsoft Graph API is a gateway to data and service management in Microsoft 365. An access token is required to call MS Graph APIs. This repo can be used obtain OAuth access token with a certificate or a secret. This approach is best suited for Admin-Consent Apps that needs access without a user, more info here.

## Usage

        String MS_TENANT_ID = "<YOUR_MS_TENANT_ID_HERE>";

        /** 1. Fetch token using certificate */
        AuthResponse response = AuthClient.fetchNewToken(MS_TENANT_ID,"cert");
        log.info("Token Response using Certificate : {}",response);

        /** 2. Fetch token using secret */
        response = AuthClient.fetchNewToken(MS_TENANT_ID,"secret");
        log.info("Token Response using Secret : {}",response);

## Explanation of Code here:

https://dev.to/brundhasv/ms-graph-api-certificate-and-client-credentials-oauth20-in-java-spring-boot-122c

