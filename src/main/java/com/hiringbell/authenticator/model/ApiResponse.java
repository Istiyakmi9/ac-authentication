package com.hiringbell.authenticator.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpStatus;

public class ApiResponse {

    @JsonProperty("AuthenticationToken")
    public String authenticationToken;
    @JsonProperty("ResponseBody")
    public Object responseBody;
    @JsonProperty("HttpStatusCode")
    public int httpStatusCode;
    @JsonProperty("HttpStatusMessage")
    public String httpStatusMessage;

    public ApiResponse(String token) {
        this.authenticationToken = token;
    }

    public ApiResponse() { }

    public static ApiResponse Ok(Object data) {
        ApiResponse response = new ApiResponse();
        response.setResponseBody(data);
        response.setHttpStatusCode(HttpStatus.OK.value());
        response.setHttpStatusMessage("successfull");
        return response;
    }

    public static ApiResponse Ok(Object data, String token) {
        ApiResponse response = new ApiResponse();
        response.setResponseBody(data);
        response.setHttpStatusMessage("successfull");
        response.setAuthenticationToken(token);
        response.setHttpStatusCode(HttpStatus.OK.value());
        return response;
    }

    public static ApiResponse BadRequest(Object data) {
        ApiResponse response = new ApiResponse();
        response.setResponseBody(data);
        response.setHttpStatusCode(HttpStatus.BAD_REQUEST.value());
        response.setHttpStatusMessage("error");
        return response;
    }

    public String getAuthenticationToken() {
        return authenticationToken;
    }

    public void setAuthenticationToken(String authenticationToken) {
        this.authenticationToken = authenticationToken;
    }

    public Object getResponseBody() {
        return responseBody;
    }

    public void setResponseBody(Object responseBody) {
        this.responseBody = responseBody;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(int httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

    public String getHttpStatusMessage() {
        return httpStatusMessage;
    }

    public void setHttpStatusMessage(String httpStatusMessage) {
        this.httpStatusMessage = httpStatusMessage;
    }
}
