package org.sparta.springauth.controller;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponse;
import org.sparta.springauth.dto.LoginRequestDto;
import org.sparta.springauth.dto.SignupRequestDto;
import org.sparta.springauth.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/login-page")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/user/signup")
    public String signupPage() {
        return "signup";
    }

    @PostMapping("/user/signup")
    public String signup(SignupRequestDto requestDto) {
        userService.signup(requestDto);

        return "redirect:/api/user/login-page";
    }
    @PostMapping("/user/login")
    public String login(LoginRequestDto requestDto, HttpServletResponse res) {
        try {
            userService.login(requestDto, res);
        } catch (Exception e) {
            return "redirect:/api/user/login-page?error=" + e.getMessage();
        }

        return "redirect:/";
    }
}