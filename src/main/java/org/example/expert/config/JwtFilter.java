package org.example.expert.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            log.info("JWT 토큰이 없거나 올바른 형식이 아닙니다.");
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authorizationHeader.substring(BEARER_PREFIX.length());

        try {
            Claims claims = jwtUtil.extractClaims(jwt);
            String username = claims.getSubject();
            UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));

            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_" + userRole.name()));

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    username, null, authorities
            );

            SecurityContextHolder.getContext().setAuthentication(authToken);

            log.info("사용자 '{}' 인증 성공. 권한: {}", username, userRole);
        } catch (ExpiredJwtException e) {
            log.error("만료된 JWT 토큰입니다.", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("토큰이 만료되었습니다. 다시 로그인해주세요.");
            return;
        } catch (MalformedJwtException e) {
            log.error("잘못된 JWT 토큰 형식입니다.", e);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("올바르지 않은 토큰 형식입니다.");
            return;

        } catch (Exception e) {
            log.error("JWT 처리 중 오류 발생", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("서버 오류가 발생했습니다.");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
