package com.hiringbell.authenticator.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.hiringbell.authenticator.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    @JsonProperty("UserDetail")
    User userDetail;

    @JsonProperty("IsAccountConfig")
    boolean isAccountConfig;

    @JsonProperty("menu")
    List<MenuAndPermission> menu;
}
