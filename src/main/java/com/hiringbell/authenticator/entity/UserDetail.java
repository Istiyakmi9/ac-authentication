package com.hiringbell.authenticator.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="user_detail")
public class UserDetail {

    @Id
    @Column(name = "UserId")
    @JsonProperty("UserId")
    long userId;

    @Column(name = "PAN")
    @JsonProperty("PAN")
    String pan;

    @Column(name = "Aadhar")
    @JsonProperty("Aadhar")
    String aadhar;

    @Column(name = "PassportNumber")
    @JsonProperty("PassportNumber")
    String passportNumber;

    @Column(name = "BankName")
    @JsonProperty("BankName")
    String bankName;

    @Column(name = "AccountNo")
    @JsonProperty("AccountNo")
    String accountNo;

    @Column(name = "Branch")
    @JsonProperty("Branch")
    String branch;

    @Column(name = "IFSCCode")
    @JsonProperty("IFSCCode")
    String IfscCode;

    @Column(name = "JobTypeId")
    @JsonProperty("JobTypeId")
    int jobTypeId;

    @Column(name = "ExperienceInMonths")
    @JsonProperty("ExperienceInMonths")
    int experienceInMonths;

    @Column(name = "lastCompanyName")
    @JsonProperty("lastCompanyName")
    String LastCompanyName;

    @Column(name = "LastWorkingDate")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonProperty("LastWorkingDate")
    Date lastWorkingDate;

    @Column(name = "Designation")
    @JsonProperty("Designation")
    String designation;

    @Column(name = "Salary")
    @JsonProperty("Salary")
    BigDecimal salary;

    @Column(name = "ExpectedSalary")
    @JsonProperty("ExpectedSalary")
    BigDecimal expectedSalary;

    @Column(name = "ExpectedDesignation")
    @JsonProperty("ExpectedDesignation")
    String expectedDesignation;

    @Column(name = "CreatedBy")
    @JsonProperty("CreatedBy")
    Long createdBy;

    @Column(name = "UpdatedBy")
    @JsonProperty("UpdatedBy")
    Long updatedBy;

    @Column(name = "CreatedOn")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonProperty("CreatedOn")
    Date createdOn;

    @Column(name = "UpdatedOn")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonProperty("UpdatedOn")
    Date updatedOn;

}
