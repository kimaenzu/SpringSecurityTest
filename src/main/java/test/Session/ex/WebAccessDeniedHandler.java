package test.Session.ex;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class WebAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 권한이 없는 경우 페이지 이동 시 사용
        response.sendRedirect("/error/error403");
        // 권한이 없는 경우 에러코드 반환 시 사용
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}