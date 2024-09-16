package com.hiringbell.authenticator.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtTokenModel {

    @JsonProperty("UserDetail")
    String userDetail;

    @JsonProperty("UserId")
    long userId;

    @JsonProperty("Email")
    String email;

    @JsonProperty("CompanyCode")
    String companyCode;

    @JsonProperty("Role")
    String role;
}
