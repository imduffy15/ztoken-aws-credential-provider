package com.amazonaws.auth;

import java.io.IOException;

public interface ZalandoTokenProvider {
    String getAccessToken() throws IOException;
}
