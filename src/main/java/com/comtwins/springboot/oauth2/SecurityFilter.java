package com.comtwins.springboot.oauth2;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.util.UUID;

@Component
@WebFilter("/*")
public class SecurityFilter extends OncePerRequestFilter {
    @Autowired
    private CacheService cacheService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain chain) throws ServletException, IOException {
        if ("GET".equalsIgnoreCase(httpServletRequest.getMethod())) {
            Cookie cookie = new Cookie("XSRF-TOKEN", UUID.randomUUID().toString());
            cookie.setHttpOnly(false);
            httpServletResponse.addCookie(cookie);
        } else if ("POST".equalsIgnoreCase(httpServletRequest.getMethod())) {
            Cookie cookie = WebUtils.getCookie(httpServletRequest, "access-token");
            if (cookie == null || cookie.getValue() == null) {
                httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
                return;
            }
            if (cacheService.get(cookie.getValue()) == null){
                httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
                return;
            }
        }

        chain.doFilter(httpServletRequest, httpServletResponse);
    }

}

