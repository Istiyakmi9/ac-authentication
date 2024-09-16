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

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="user_medical_detail")
public class UserMedicalDetail {

    @Id
    @Column(name = "UserMedicalDetailId")
    @JsonProperty("UserMedicalDetailId")
    long userMedicalDetailId;

    @Column(name = "UserId")
    @JsonProperty("UserId")
    long userId;

    @Column(name = "MedicalConsultancyId")
    @JsonProperty("MedicalConsultancyId")
    long medicalConsultancyId;

    @Column (name = "ConsultedBy")
    @JsonProperty("ConsultedBy")
    String ConsultedBy;

    @Column(name = "ConsultedOn")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @JsonProperty("ConsultedOn")
    Date consultedOn;

    @Column(name = "ReferenceId")
    @JsonProperty("ReferenceId")
    long referenceId;

    @Column(name = "ReportId")
    @JsonProperty("ReportId")
    long reportId;

    @Column(name = "ReportPath")
    @JsonProperty("ReportPath")
    String ReportPath;

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
