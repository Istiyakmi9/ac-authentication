package com.hiringbell.authenticator.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.gson.JsonParser;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class JwtUtil {
    private final static Logger LOGGER = LoggerFactory.getLogger(JwtUtil.class);
    private static final String SECRET_KEY = "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";

    public Map<String, Object> validateToken(String token) {
        // Claims claims = null;
        Map<String, Object> userDetails = new HashMap<>();
        Map<String, Object> claims = null;
        try {

            HttpTransport httpTransport = new NetHttpTransport();
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(httpTransport, JacksonFactory.getDefaultInstance())
                    .setAudience(Collections.singletonList("622966386962-pcep2a9p2l0j75p1nrl5m7clhlln3eil.apps.googleusercontent.com"))
//                    .setAudience(Collections.singletonList("532816585614-335gusa42uce2jedsg6hffvqr8kb630n.apps.googleusercontent.com"))
                    .build();

            // Verify it
            GoogleIdToken idToken = verifier.verify(token);

            GoogleIdToken.Payload payload = idToken.getPayload();
            String name = (String) payload.get("name");
            String email = payload.getEmail();

            userDetails.put("name", name);
            userDetails.put("email", email);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage());
        }

        return userDetails;
    }

    public Map<String, Object> ValidateGoogleAuthToken(String accessToken) {
        final String TOKEN_INFO_URL = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=";
        Map<String, Object> userDetails = new HashMap<>();
        Map<String, Object> claims = null;
        try {
            String url = TOKEN_INFO_URL + accessToken;
            try (var httpClient = HttpClients.createDefault()) {
                var request = new HttpGet(url);
                try (var response = httpClient.execute(request)) {
                    if (response.getCode() == 200) {
                        var jsonResponse = EntityUtils.toString(response.getEntity());
                        var jsonObject = JsonParser.parseString(jsonResponse).getAsJsonObject();
                        String _clientId = jsonObject.get("audience").getAsString();
                        String email = jsonObject.get("email").getAsString();
                        userDetails.put("email", email);
                    }
                }
            }
            // add remaining logic here
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage());
        }
        return userDetails;
    }
}