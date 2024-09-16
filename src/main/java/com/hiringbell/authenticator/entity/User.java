package com.hiringbell.authenticator.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long userId;

    String firstName;

    String lastName;

    String address;

    String mobileNumber;

    String alternateNumber;

    String emailId;

    String accountId;

    Long referenceId;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    Date dob;

    Long createdBy;

    Long updatedBy;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    Date createdOn;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    Date updatedOn;

    @Transient
    @JsonProperty("token")
    String token;

    @Transient
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    Date tokenExpiryDuration;
}
