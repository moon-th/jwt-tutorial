package me.moonth.tutorial.service;

import me.moonth.tutorial.dto.UserDto;
import me.moonth.tutorial.entity.Authority;
import me.moonth.tutorial.entity.User;
import me.moonth.tutorial.repository.UserRepository;
import me.moonth.tutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional //회원가입 로직
    public User Signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }
        //권한정보 입력
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        //유저 정보 입력
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return userRepository.save(user);
    }

    //넘겨받은 username 에 대한 정보를 가져오는 파라미터
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    //SecurityContext에 저장된 username 의 정보만 가져옵니다.
    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities(){
        return SecurityUtil.getCurrentUsername().flatMap(username -> userRepository.findOneWithAuthoritiesByUsername(username));
    }
}
