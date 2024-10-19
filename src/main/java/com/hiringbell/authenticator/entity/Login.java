package com.hiringbell.authenticator.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Data;

import java.util.Date;

@Data
@Entity
@Table(name="login")
public class Login {
    @Id
    @JsonProperty("loginId")
    Long loginId;

    @JsonProperty("employeeId")
    Long employeeId;

    @JsonProperty("emailId")
    String emailId;

    @JsonProperty("mobileNumber")
    String mobileNumber;

    @JsonProperty("password")
    String password;

    @JsonProperty("userTypeId")
    int userTypeId;

    @JsonProperty("createdBy")
    Long createdBy;

    @JsonProperty("updatedBy")
    Long updatedBy;

    @JsonProperty("createdOn")
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss")
    Date createdOn;

    @JsonProperty("updatedOn")
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss")
    Date updatedOn;

    @JsonProperty("newPassword")
    @Transient
    String newPassword;
}
