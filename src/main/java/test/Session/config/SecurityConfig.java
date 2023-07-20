package test.Session.config;
/*
시큐리티 관련 기능을 쉽게 설정하기 위해서 WebSecurityConfigurerAdapter라는 클래스를 상속해서 처리한다.
Override를 통해서 여러 설정 조정
 */

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@Log4j2
public class SecurityConfig {
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
        http.authorizeRequests((auth) -> {
            auth.requestMatchers( "/sample/all.html").permitAll();
            auth.requestMatchers("/sample/member.html").hasRole("USER");
            auth.requestMatchers("/sample/manager.html").hasRole("MEMBER");
            auth.requestMatchers("/sample/admin.html").hasRole("ADMIN");
        });
        http.formLogin(Customizer.withDefaults());
        http.csrf(c -> c
                .disable());
        http.logout(l -> l
                .logoutUrl("/logout")
                .logoutSuccessUrl("/sample/all.html"));

        return http.build();
    }
}
