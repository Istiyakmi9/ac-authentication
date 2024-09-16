package com.hiringbell.authenticator.jwtconfig;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hiringbell.authenticator.model.JwtTokenModel;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class JwtGateway {

    private static JwtGateway jwtGateway;
    private JwtGateway(){

    }

    // creating singleton object
    public static JwtGateway getJwtGateway() {
        if (jwtGateway == null) {
            synchronized (JwtGateway.class) {
                if (jwtGateway == null) {
                    jwtGateway = new JwtGateway();
                }
            }
        }
        return jwtGateway;
    }

    public String generateJwtToken(JwtTokenModel jwtTokenModel) throws IOException {
        String tokenResult = null;
        try {
            // Specify the URL you want to send the POST request to
            URL url = new URL("https://www.bottomhalf.in/api/tokenmanager/generatetoken");

            // Open a connection to the URL
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // Set the request method to POST
            connection.setRequestMethod("POST");

            // Enable input/output streams
            connection.setDoOutput(true);

            // Set the request headers (if needed)
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");

            // Create the request body (if needed)
            ObjectMapper mapper = new ObjectMapper();
            String jwtTokenModelJson = mapper.writeValueAsString(jwtTokenModel);
            String requestBody = jwtTokenModelJson;

            // Get the output stream and write the request body to it
            try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                wr.writeBytes(requestBody);
                wr.flush();
            }

            // Get the response code
            int responseCode = connection.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            // Read the response from the server
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }

                // Print the response
                System.out.println("Response: " + response.toString());
                tokenResult = response.toString().replaceAll("\"", "");
            }

            // Close the connection
            connection.disconnect();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return tokenResult;
    }

}
