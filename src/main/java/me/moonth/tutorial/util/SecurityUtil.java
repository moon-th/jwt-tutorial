package me.moonth.tutorial.util;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public class SecurityUtil {

    private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    private SecurityUtil() {

    }


    public static Optional<String> getCurrentUsername() {
        //Security Context 에서 authentication 객체를 추출
        //Security Context 에 authentication 객체가 저장되는 시점은 JwtFilter 의 doFilter 메소드 에서
        //Request 가 들어올 때 Security Context 에 authentication 객체를 저장해서 사용
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            logger.debug("Security Context 에 인증 정보가 없습니다.");
            return Optional.empty();
        }

        String username = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            //authentication 에서 UserDetails 객체를 추출
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            //UserDetails username 을 추출 한다
            username = springSecurityUser.getUsername();
        }else if(authentication.getPrincipal() instanceof  String){
            username = (String) authentication.getPrincipal();
        }
        return Optional.ofNullable(username);
    }
}
