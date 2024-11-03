package com.msgraph.clientcreds.common;

public class Constants {
    //ms app client/app id
    public static final String MS_APP_CLIENT_ID = "<YOUR_MS_APPLICATION_ID_HERE>";

    //client secret
    public static String MS_APP_CLIENT_SECRET = "<YOUR_MS_CLIENT_SECRET_HERE>";

    //ms graph api oauth token url
    public static final String MS_APP_TOKEN_URL =
            "https://login.microsoftonline.com/%s/oauth2/v2.0/token";

    //ms graph api oauth token url
    public static final String MS_APP_TOKEN_SCOPE = "https://graph.microsoft.com/.default";

    //client certificate details
    public static final String CERT_PATH = "<YOUR_CERT_PATH_HERE>";
    public static final String CERT_KEY_PATH = "<YOUR_CERT_KEY_PATH_HERE>";
}
