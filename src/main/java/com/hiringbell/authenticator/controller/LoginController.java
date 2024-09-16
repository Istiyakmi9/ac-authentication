package com.hiringbell.authenticator.controller;

import com.hiringbell.authenticator.contract.ILoginService;
import com.hiringbell.authenticator.entity.Login;
import com.hiringbell.authenticator.entity.User;
import com.hiringbell.authenticator.model.ApiResponse;
import com.hiringbell.authenticator.model.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/oauth")
public class LoginController {
    @Autowired
    ILoginService loginService;

    @PostMapping("/googlelogin")
    public ResponseEntity<ApiResponse> registerWithGoogle(@RequestBody User user) throws Exception {
        var result = loginService.userAuthetication(user);
        return ResponseEntity.ok(ApiResponse.Ok(result));
    }

    @GetMapping("/remove_user")
    public ResponseEntity<ApiResponse> remove_user() {
        var result = "your account deleted successfully";
        return ResponseEntity.ok(ApiResponse.Ok(result));
    }


    @PostMapping("/googlemobilelogin")
    public ResponseEntity<ApiResponse> registerWithGoogleMobile(@RequestBody User user) throws Exception {
        var result = loginService.userAutheticationMobile(user);
        return ResponseEntity.ok(ApiResponse.Ok(result));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<ApiResponse> authenticate(@RequestBody Login login) throws Exception {
        var result = loginService.authenticateUserService(login);
        return ResponseEntity.ok(ApiResponse.Ok(result));
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse> signup(@RequestBody Login login) throws Exception {
        var result = this.loginService.signupService(login);
        return ResponseEntity.ok(ApiResponse.Ok(result));
    }

    @PostMapping("/shortsignup")
    public ResponseEntity<ApiResponse> shortsignup(@RequestBody Login login) throws Exception {
        var result = this.loginService.shortSignupService(login);
        return ResponseEntity.ok(ApiResponse.Ok(result));
    }
}