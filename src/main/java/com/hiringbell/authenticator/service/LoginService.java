package com.hiringbell.authenticator.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hiringbell.authenticator.contract.ILoginService;
import com.hiringbell.authenticator.db.LowLevelExecution;
import com.hiringbell.authenticator.entity.Login;
import com.hiringbell.authenticator.entity.User;
import com.hiringbell.authenticator.entity.UserDetail;
import com.hiringbell.authenticator.entity.UserMedicalDetail;
import com.hiringbell.authenticator.jwtconfig.JwtGateway;
import com.hiringbell.authenticator.model.ApplicationConstant;
import com.hiringbell.authenticator.model.DbParameters;
import com.hiringbell.authenticator.model.JwtTokenModel;
import com.hiringbell.authenticator.model.LoginResponse;
import com.hiringbell.authenticator.repository.LoginRepository;
import com.hiringbell.authenticator.repository.UserRepository;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.math.BigDecimal;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.*;

@Service
public class LoginService implements ILoginService {
    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    LoginRepository loginRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    LowLevelExecution lowLevelExecution;
    @Autowired
    ObjectMapper objectMapper;

    public LoginResponse userAuthetication(User user) throws Exception {
        Map<String, Object> result = jwtUtil.validateToken(user.getToken());
        return userAuthenticateByEmail(user, result);
    }

    public LoginResponse userAutheticationMobile(User user) throws Exception {
        Map<String, Object> result = jwtUtil.ValidateGoogleAuthToken(user.getToken());
        return userAuthenticateByEmail(user, result);
    }

    private @NotNull LoginResponse userAuthenticateByEmail(User user, Map<String, Object> result) throws Exception {
        if (!result.get("email").equals(user.getEmailId()))
            throw new Exception("Invalid email used");

        var data = getgUserByEmailOrMobile(user.getEmailId(), "");
        User userdetail = null;
        var isAccountConfig = false;
        if (data == null || data.get("LoginDetail") == null) {
            userdetail = addUserService(user);
            isAccountConfig = false;
        } else {
            userdetail = (User) data.get("UserDetail");
            Login loginDetail = (Login) data.get("LoginDetail");
        }
        var loginResponse = getLoginResponse(userdetail, 0);
        loginResponse.setAccountConfig(isAccountConfig);
        return loginResponse;
    }

    public LoginResponse authenticateUserService(Login login) throws Exception {
        try {
            validateLoginDetail(login);
            var data = getgUserByEmailOrMobile(login.getEmailId(), login.getMobileNumber());
            if (data == null || data.get("LoginDetail") == null)
                throw new Exception("Login detail not found");

            Login loginDetail = (Login) data.get("LoginDetail");
            if (loginDetail == null)
                throw new Exception("Login detail not found");

            validateCredential(loginDetail, login);
            //User user = (User) data.get("UserDetail");
            User user = new User();
            user.setUserId(1L);
            user.setUserId(1L);
            user.setEmailId(login.getEmailId());
            var loginResponse = getLoginResponse(user, loginDetail.getUserTypeId());
            return loginResponse;
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    private Map<String, Object> getgUserByEmailOrMobile(String email, String mobile) throws Exception {
        var dataSet = lowLevelExecution.executeProcedure("sp_employeelogin_auth",
                Arrays.asList(
                        new DbParameters("_mobileNumber", mobile, Types.VARCHAR),
                        new DbParameters("_emailId", email, Types.VARCHAR)
                )
        );
        if (dataSet == null || dataSet.size() != 3)
            throw new Exception("Fail to get user detail. Please contact to admin.");

        List<User> users = objectMapper.convertValue(dataSet.get("#result-set-1"), new TypeReference<List<User>>() {
        });
        List<Login> logins = objectMapper.convertValue(dataSet.get("#result-set-2"), new TypeReference<List<Login>>() {
        });
        if (logins.isEmpty())
            return null;

        Map<String, Object> response = new HashMap<>();
        //response.put("UserDetail", users.get(0));
        response.put("LoginDetail", logins.get(0));
        return response;
    }

    @Transactional(rollbackFor = Exception.class)
    private User addUserService(User user) throws Exception {
        Date utilDate = new Date();
        var currentDate = new Timestamp(utilDate.getTime());
        var lastUserId = userRepository.getLastUserId();
        if (lastUserId == null)
            user.setUserId(1L);
        else
            user.setUserId(lastUserId.getUserId() + 1);

        userRepository.save(user);

        Login loginDetail = getLogin(currentDate, user);
        this.loginRepository.save(loginDetail);

        UserDetail userDetail = new UserDetail();
        userDetail.setUserId(user.getUserId());
        userDetail.setJobTypeId(0);
        userDetail.setExperienceInMonths(0);
        userDetail.setLastWorkingDate(currentDate);
        userDetail.setSalary(BigDecimal.ZERO);
        userDetail.setExpectedSalary(BigDecimal.ZERO);
        userDetail.setCreatedBy(user.getUserId());
        userDetail.setCreatedOn(currentDate);

        return user;
    }

    @NotNull
    private  Login getLogin(Timestamp currentDate, User user) {
        Login loginDetail = new Login();
        var lastLoginRecord = this.loginRepository.getLastLoginRecord();
        if (lastLoginRecord == null) {
            loginDetail.setLoginId(1L);
        } else {
            loginDetail.setLoginId(lastLoginRecord.getLoginId() + 1);
        }
        loginDetail.setPassword(ApplicationConstant.DefaultPassword);
        loginDetail.setCreatedBy(user.getUserId());
        loginDetail.setCreatedOn(currentDate);
        return loginDetail;
    }

    private LoginResponse getLoginResponse(User user, int roleId) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        String userDetailJson = mapper.writeValueAsString(user);
        JwtTokenModel jwtTokenModel = new JwtTokenModel();
        jwtTokenModel.setUserDetail(userDetailJson);
        jwtTokenModel.setUserId(user.getUserId());
        jwtTokenModel.setEmail(user.getEmailId());
        jwtTokenModel.setCompanyCode("AX-000");
        switch (roleId) {
            case 1:
                jwtTokenModel.setRole(ApplicationConstant.Admin);
                break;
            case 3:
                jwtTokenModel.setRole(ApplicationConstant.Client);
                break;
            default:
                jwtTokenModel.setRole(ApplicationConstant.User);
        }

        JwtGateway jwtGateway = JwtGateway.getJwtGateway();
        String result = jwtGateway.generateJwtToken(jwtTokenModel);

        LoginResponse loginResponse = new LoginResponse();
        Date oldDate = new Date(); // oldDate == current time
        final long hoursInMillis = 60L * 60L * 1000L;
        Date newDate = new Date(oldDate.getTime() + (2L * hoursInMillis)); // Adds 2 hours
        user.setToken(result);
        user.setTokenExpiryDuration(newDate);
        loginResponse.setUserDetail(user);
        return loginResponse;
    }

    private void validateCredential(Login login, Login request) throws Exception {
//        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
//        String password = encoder.encode(request.getPassword());
//        if(!encoder.matches(password, login.getPassword())) {
//            user = userService.getByUserMobileService(request.getMobile());
//        } else {
//            throw new Exception("Invalid username or password.");
//        }
        if (!login.getPassword().equals(request.getPassword()))
            throw new Exception("Password is not matched");
    }

    private void validateLoginDetail(Login login) throws Exception {
        if (login.getPassword() == null || login.getPassword().isEmpty())
            throw new Exception("Password is required");

        if ((login.getEmailId() == null || login.getEmailId().isEmpty()) && (login.getMobileNumber() == null || login.getMobileNumber().isEmpty()))
            throw new Exception("Email or Mobile number is required");
    }

    @Transactional(rollbackFor = Exception.class)
    public LoginResponse signupService(Login login) throws Exception {
        Date utilDate = new Date();
        var currentDate = new Timestamp(utilDate.getTime());

        User user = new User();

        var lastUserId = userRepository.getLastUserId();
        if (lastUserId == null)
            user.setUserId(1L);
        else
            user.setUserId(lastUserId.getUserId() + 1);

        String[] splitStr = new String[] {""};
        if (splitStr.length == 1)
            user.setFirstName(splitStr[0]);
        else {
            user.setFirstName(splitStr[0]);
            user.setLastName(splitStr[1]);
        }
        user.setCreatedOn(currentDate);
        userRepository.save(user);

        Login loginDetail = new Login();
        var lastLoginRecord = this.loginRepository.getLastLoginRecord();
        if (lastLoginRecord == null) {
            loginDetail.setLoginId(1L);
        } else {
            loginDetail.setLoginId(lastLoginRecord.getLoginId() + 1);
        }
        loginDetail.setPassword(login.getPassword());
        loginDetail.setCreatedBy(user.getUserId());
        loginDetail.setCreatedOn(currentDate);
        this.loginRepository.save(loginDetail);

        UserDetail userDetail = new UserDetail();
        userDetail.setUserId(user.getUserId());
        userDetail.setJobTypeId(0);
        userDetail.setExperienceInMonths(0);
        userDetail.setLastWorkingDate(currentDate);
        userDetail.setSalary(BigDecimal.ZERO);
        userDetail.setExpectedSalary(BigDecimal.ZERO);
        userDetail.setCreatedBy(user.getUserId());
        userDetail.setCreatedOn(currentDate);

        UserMedicalDetail userMedicalDetail = new UserMedicalDetail();
        userMedicalDetail.setUserId(user.getUserId());
        userMedicalDetail.setMedicalConsultancyId(0);
        userMedicalDetail.setConsultedOn(currentDate);
        userMedicalDetail.setReferenceId(0L);
        userMedicalDetail.setReportId(0);
        userMedicalDetail.setCreatedBy(user.getUserId());
        userMedicalDetail.setCreatedOn(currentDate);
        return null;
    }

    @Transactional(rollbackFor = Exception.class)
    public LoginResponse shortSignupService(Login login) throws Exception {
        Date utilDate = new Date();
        var currentDate = new Timestamp(utilDate.getTime());

        User user = new User();
        var lastUserId = userRepository.getLastUserId();
        if (lastUserId == null)
            user.setUserId(1L);
        else
            user.setUserId(lastUserId.getUserId() + 1);

        String[] splitStr = new String[] {""};
        if (splitStr.length == 1)
            user.setFirstName(splitStr[0]);
        else if (splitStr.length > 1) {
            user.setFirstName(splitStr[0]);
            user.setLastName(splitStr[1]);
        }

        user.setCreatedOn(currentDate);
        userRepository.save(user);

        Login loginDetail = new Login();
        var lastLoginRecord = this.loginRepository.getLastLoginRecord();
        if (lastLoginRecord == null) {
            loginDetail.setLoginId(1L);
        } else {
            loginDetail.setLoginId(lastLoginRecord.getLoginId() + 1);
        }

        this.loginRepository.save(loginDetail);

        LoginResponse loginResponse = getLoginResponse(user, loginDetail.getUserTypeId());
        return loginResponse;
    }

}