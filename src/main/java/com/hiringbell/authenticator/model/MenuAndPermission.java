package com.hiringbell.authenticator.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MenuAndPermission {
    @JsonProperty("catagory")
    String catagory;

    @JsonProperty("childs")
    String childs;

    @JsonProperty("link")
    String link;

    @JsonProperty("icon")
    String icon;

    @JsonProperty("badge")
    String badge;

    @JsonProperty("badgeType")
    String badgeType;

    @JsonProperty("accessCode")
    int accessCode;

    @Transient
    @JsonProperty("permission")
    int permission;

    @Transient
    @JsonProperty("ParentMenu")
    String parentMenu;
}
