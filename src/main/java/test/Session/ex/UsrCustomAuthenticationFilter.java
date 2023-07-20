package test.Session.ex;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


public class UsrCustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    public UsrCustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(request.getParameter("usrId"), request.getParameter("usrPw"));

        System.out.println("*********************************************************************");
        System.out.println("[UsrCustomAuthenticationFilter] UsernamePasswordAuthenticationToken 생성");
        System.out.println("usrId : " + request.getParameter("usrId").toString());
        System.out.println("usrPw : " + request.getParameter("usrPw").toString());
        System.out.println("*********************************************************************");

        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }
}