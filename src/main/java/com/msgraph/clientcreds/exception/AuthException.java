package com.msgraph.clientcreds.exception;

public class AuthException extends RuntimeException {
    private static final String PREFIX = "[MS-Auth]";
    static String constructMessage(
            final String prefix, final String cause, final String exception) {
        return prefix + cause + ">\n" + exception;
    }

    public AuthException(final String cause, final String exception) {
        super(constructMessage(PREFIX, cause, exception));
    }
}
