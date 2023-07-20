package test.Session.ex;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;

        // AuthenticaionFilter에서 생성된 토큰으로부터 아이디와 비밀번호를 조회함
        String userId = token.getName();
        String userPw = (String) token.getCredentials();

        UserDTO uDTO = new UserDTO();
        // ... DB에서 아이디로 사용자 조회

        // 비밀번호 일치 여부 체크
        if (!passwordEncoder.matches(userPw, uDTO.getUsrPw())) {
            throw new BadCredentialsException(uDTO.getUsrId() + " Invalid password");
        }

        // principal(접근대상 정보), credential(비밀번호), authorities(권한 목록)를 token에 담아 반환
        return new UsernamePasswordAuthenticationToken(uDTO, userPw, uDTO.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
