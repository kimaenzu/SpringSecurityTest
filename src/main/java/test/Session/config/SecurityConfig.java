package test.Session.config;
/*
시큐리티 관련 기능을 쉽게 설정하기 위해서 WebSecurityConfigurerAdapter라는 클래스를 상속해서 처리한다.
Override를 통해서 여러 설정 조정
 */

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import test.Session.jwt.JwtAuthenticationFilter;
import test.Session.jwt.JwtTokenProvider;
import test.Session.security.dto.TokenDto;
import test.Session.security.service.MemService;
import test.Session.security.service.UserDS;

@Configuration
@Log4j2
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDS userDS;


    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails user = User.builder().username("user1").password(passwordEncoder().encode("1111")).roles("USER").build();
//        log.info("userDetailsService.................");
//        log.info(user);
//
//        return new InMemoryUserDetailsManager(user);
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("start filterChain");
        http.authorizeRequests((auth) -> {
            auth.requestMatchers( "/sample/all").permitAll();
            auth.requestMatchers("/sample/member").hasRole("USER");
            auth.requestMatchers("/sample/manager").hasRole("MEMBER");
            auth.requestMatchers("/sample/admin").hasRole("ADMIN");
            auth.requestMatchers("/sample/login").permitAll();
        }).addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
        log.info("ended JwtAuthenticationFilter");

        http.formLogin(Customizer.withDefaults());
        http.csrf(c -> c
                .disable());
        http.logout(l -> l
                .logoutUrl("/logout")
                .logoutSuccessUrl("/sample/all.html"));

        return http.build();
    }
}
