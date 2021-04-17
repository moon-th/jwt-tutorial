package me.moonth.tutorial.jwt;

import com.sun.xml.bind.v2.runtime.unmarshaller.XsiNilLoader;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import me.moonth.tutorial.entity.User;
import org.hibernate.mapping.Array;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.validation.Valid;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final Long tokenValidityInMillisecondes;

    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValiditySeconds){
        this.secret = secret;
        this.tokenValidityInMillisecondes = tokenValiditySeconds * 1000;

    }

    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret); // 주입받은 값을 BASE64 를 사용 하여 디코드
        this.key = Keys.hmacShaKeyFor(keyBytes); // 디코드 후 Key 변수에 할당
    }

    //권한 정보를 이용해서 토큰을 생성하는 메서드
    public String createToken(Authentication authentication){
        //권한 셋팅
        String authorities = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(","));


        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMillisecondes);

        //토큰 샐성 후 리턴
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

     //Token 에 담겨있는 정보를 이용해 Authentication 객체를 리턴하는 메서드 생성
    public Authentication getAuthentication(String token) {

        //token 을 이용해서 Claim 객체생성
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        //Claim 에서 권한정보 들을 추출하여 유저 객체를 만들어 준다.
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(),"", authorities);

        //Authentication 객체를 리턴
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    //토큰의 유효성 검사를 수행하는 validateToken 메소드 추가
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

}
