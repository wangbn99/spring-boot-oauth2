package com.comtwins.springboot.oauth2;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.revoke.TokenTypeHint;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;

@Component
@RequiredArgsConstructor
public class CacheService {
    private final Cache<String, CacheConfig.Entry<Object>> cache;
    private final HttpServletRequest httpServletRequest;
    private final HttpServletResponse httpServletResponse;
    private final OAuth2ServiceFactory oAuth2ServiceFactory;

    private final Logger logger = LoggerFactory.getLogger(CacheService.class);

    public void put(String key, Object value, Duration timeout) {
        cache.put(key, new CacheConfig.Entry<Object>(value, timeout));
    }

    public Object get(String key) {
        CacheConfig.Entry<Object> entry = cache.getIfPresent(key);
        if (entry != null){
            if (System.currentTimeMillis() < entry.getCreateAt() + entry.getTimeout().toMillis()) {
                return entry.getValue();
            } else {
                cache.invalidate(key);
                logger.info("get expired value for key = {}", key);
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public void invalidate(String AccessToken) {
        if (AccessToken != null) {
            Map<String, String> map = (HashMap<String, String>) get(AccessToken);
            String serviceId = map.get("serviceId");
            OAuth20Service oAuth20Service = oAuth2ServiceFactory.getService(serviceId);
            try {
                String revokeTokenEndpoint = oAuth20Service.getApi().getRevokeTokenEndpoint();
                if (Objects.equals("facebook", serviceId)) {
                    final OAuthRequest oAuthRequest = new OAuthRequest(Verb.DELETE, revokeTokenEndpoint.replace("{user-id}", map.get("id")));
                    oAuth20Service.signRequest(AccessToken, oAuthRequest);
                    oAuth20Service.execute(oAuthRequest);

                } else if (StringUtils.hasText(revokeTokenEndpoint)) {
                    oAuth20Service.revokeToken(AccessToken, TokenTypeHint.ACCESS_TOKEN);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        cache.invalidate(AccessToken);
    }
}
