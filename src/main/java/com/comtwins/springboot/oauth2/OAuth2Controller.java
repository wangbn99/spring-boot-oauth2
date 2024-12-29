package com.comtwins.springboot.oauth2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutionException;

@RestController
@RequiredArgsConstructor
public class OAuth2Controller {
    private final OAuth2ServiceFactory oAuth2ServiceFactory;
    private final ObjectMapper objectMapper;
    private final CacheService cache;
    private final HttpServletRequest httpServletRequest;
    private final HttpServletResponse httpServletResponse;

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Controller.class);

    @GetMapping("/oauth2/authorization/{serviceId}")
    public RedirectView oauth2Login(@PathVariable String serviceId) {
        String state = UUID.randomUUID().toString();
        cache.put(state, serviceId + " state", Duration.ofMinutes(5));
        logger.info("auth state: {} for {}, {}", state, serviceId, cache.get(state));

        String redirectUrl = oAuth2ServiceFactory.getService(serviceId).getAuthorizationUrl(state);
        logger.info("redirect to {}", redirectUrl);
        return new RedirectView(redirectUrl);
    }

    @GetMapping("/oauth2/code/{serviceId}")
    public void oauth2Code(@PathVariable String serviceId, @RequestParam String code, @RequestParam String state) throws InterruptedException, ExecutionException, IOException {
        logger.info("call back from auth provider {} with code = {} and state = {}", serviceId, code, state);
        if (cache.get(state) == null) {
            httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
            logger.info("couldn't be found state = {}", state);
        } else {
            OAuth20Service oAuth20Service = oAuth2ServiceFactory.getService(serviceId);
            OAuth2AccessToken oAuth2AccessToken = oAuth20Service.getAccessToken(code);

            String accessToken = oAuth2AccessToken.getAccessToken();
            logger.info("received access token {} from {}", accessToken, serviceId);

            Cookie cookie = new Cookie("access-token", accessToken);
            cookie.setHttpOnly(true);
            cookie.setMaxAge(15*60);
            cookie.setPath("/");
            httpServletResponse.addCookie(cookie);

            OAuth2ServiceFactory.OAuth2Api oAuth2Api = (OAuth2ServiceFactory.OAuth2Api)oAuth20Service.getApi();
            final OAuthRequest oAuthRequest = new OAuthRequest(Verb.GET, oAuth2Api.getUserInfoEndpoint());
            oAuth20Service.signRequest(oAuth2AccessToken, oAuthRequest);
            String userInfo = oAuth20Service.execute(oAuthRequest).getBody();
            TypeReference<HashMap<String,Object>> typeRef = new TypeReference<HashMap<String,Object>>() {};
            Map<String, Object> userInfoMap = objectMapper.readValue(oAuth20Service.execute(oAuthRequest).getBody(), typeRef);
            logger.info("got user info {}", userInfoMap);
            Map<String, String> map = new HashMap<>();
            map.put("serviceId", serviceId);
            map.put("username", (String)userInfoMap.get(oAuth2Api.getUserNameAttribute()));
            if (userInfoMap.containsKey("id")) {
                map.put("id", String.valueOf(userInfoMap.get("id")));
            }
            int expiresIn = Optional.ofNullable(oAuth2AccessToken.getExpiresIn()).orElse(3600);

            logger.info("cached {}", map);

            cache.put(accessToken, map, Duration.ofSeconds(expiresIn));
        }
        httpServletResponse.sendRedirect("/");
    }

    @SuppressWarnings("unchecked")
    @GetMapping("/user")
    public Map<String, String> user() {
        Cookie cookie = WebUtils.getCookie(httpServletRequest, "access-token");
        if (cookie != null) {
            String accessToken = cookie.getValue();
            if (accessToken != null) {
                Map<String, String> map = (HashMap<String, String>) cache.get(accessToken);
                logger.info("return value for get /user: {}", map);
                return map;
            }
        }
        return null;
    }

    @PostMapping("/logout")
    public void logout() {
        Cookie cookie = WebUtils.getCookie(httpServletRequest, "access-token");
        if (cookie != null){
            String accessToken = cookie.getValue();
            if (accessToken != null) {
                cache.invalidate(accessToken);
                cookie.setMaxAge(0);
                httpServletResponse.addCookie(cookie);
            }

            httpServletRequest.getSession().invalidate();
        }
    }

}
