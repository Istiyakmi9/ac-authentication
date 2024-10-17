package com.hiringbell.authenticator.config;

import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
public class ApplicationException extends RuntimeException {
    String userErrorMessage;
    int StatusCode;

    public ApplicationException(String message, Exception ex) {
        super(message, ex);
    }

    public static ApplicationException ThrowBadRequest(String message, Exception ex) {
        var exception = new ApplicationException(message, ex);
        exception.setStatusCode(HttpStatus.BAD_REQUEST.value());
        exception.setUserErrorMessage(message);
        return exception;
    }
}
