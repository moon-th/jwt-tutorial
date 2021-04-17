package me.moonth.tutorial.controller;

import me.moonth.tutorial.dto.UserDto;
import me.moonth.tutorial.entity.User;
import me.moonth.tutorial.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }


    //회원가입
    @PostMapping("/signup")
    public ResponseEntity<User> signup(
            @Valid @RequestBody UserDto userDto
    ) {
        return ResponseEntity.ok(userService.Signup(userDto));
    }

    //@PreAuthorize("hasAnyRole('USER','ADMIN')") 사용하여 두가지 ROLE 를 모두 호출할 수 있는 API
    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<User> getMyUserInfo() {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }
    //@PreAuthorize("hasAnyRole('ADMIN')") 사용하여 한가지 ROLE 만 가지고 온다.
    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}

