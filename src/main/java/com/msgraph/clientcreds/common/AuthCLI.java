package com.msgraph.clientcreds.common;

import com.msgraph.clientcreds.auth.AuthClient;
import com.msgraph.clientcreds.model.AuthResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthCLI implements CommandLineRunner {

    @Override
    public void run(String... args) throws Exception {
        String MS_TENANT_ID = "<YOUR_MS_TENANT_ID_HERE>";

        /** 1. Fetch token using certificate */
        AuthResponse response = AuthClient.fetchNewToken(MS_TENANT_ID,"cert");
        log.info("Token Response using Certificate : {}",response);

        /** 2. Fetch token using secret */
        response = AuthClient.fetchNewToken(MS_TENANT_ID,"secret");
        log.info("Token Response using Secret : {}",response);
    }
}
