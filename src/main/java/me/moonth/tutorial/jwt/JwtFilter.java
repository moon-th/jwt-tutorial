package me.moonth.tutorial.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private TokenProvider tokenProvider;

    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    //실제 필터링 로직이 들어가는 메서드
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        //Http request 가져오기
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        //request 에서 token 추출
        String jwt = resolveToken(httpServletRequest);
        String requestURI = httpServletRequest.getRequestURI();

        //jwt 유효성 검사 메소드를 사용하여 검증
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            //token 이 정상적이면 authentication 객체를 받아온다
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            // 받아온 authentication 객체를 SecurityContext 에 넣어준다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context 에 '{}' 인증 정보를 저장 했습니다. uri:{}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다., uri:{}",requestURI);
        }

        chain.doFilter(request,response);
    }

    //Request Header 에서 토큰 정보를 꺼내오기 위한 resolve Token 메소드 추가
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }

}
