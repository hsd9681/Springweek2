package org.sparta.springauth.service;

import jakarta.servlet.http.HttpServletResponse;
import org.sparta.springauth.dto.LoginRequestDto;
import org.sparta.springauth.dto.SignupRequestDto;
import org.sparta.springauth.entity.User;
import org.sparta.springauth.entity.UserRoleEnum;
import org.sparta.springauth.jwt.JwtUtil;
import org.sparta.springauth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = new JwtUtil();
    }

    // ADMIN_TOKEN
    private final String ADMIN_TOKEN = "AAABnvxRVklrnYxKZ0aHgTBcXukeZygoC";

    public void signup(SignupRequestDto requestDto) {
        String username = requestDto.getUsername();
        String password = passwordEncoder.encode(requestDto.getPassword());

        // 회원 중복 확인
        Optional<User> checkUsername = userRepository.findByUsername(username);
        if (checkUsername.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자가 존재합니다.");
        }

        // email 중복확인
        String email = requestDto.getEmail();
        Optional<User> checkEmail = userRepository.findByEmail(email);
        if (checkEmail.isPresent()) {
            throw new IllegalArgumentException("중복된 Email 입니다.");
        }

        // 사용자 ROLE 확인
        UserRoleEnum role = UserRoleEnum.USER;
        if (requestDto.isAdmin()) {
            if (!ADMIN_TOKEN.equals(requestDto.getAdminToken())) {
                throw new IllegalArgumentException("관리자 암호가 틀려 등록이 불가능합니다.");
            }
            role = UserRoleEnum.ADMIN;
        }

        // 사용자 등록
        User user = new User(username, password, email, role);
        userRepository.save(user);
    }

    public void login(LoginRequestDto requestDto, HttpServletResponse res) {
        String username = requestDto.getUsername();
        String password = requestDto.getPassword();

        //user check
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new IllegalArgumentException("등록된 사용자가 없습니다.")
        );
        //비번 확인
        if(!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("password mismatch");
        }
        //jwt 생성 및 저장
        String token  = jwtUtil.createToken(user.getUsername(), user.getRole());
        jwtUtil.addJwtToCookie(token, res);
    }
}