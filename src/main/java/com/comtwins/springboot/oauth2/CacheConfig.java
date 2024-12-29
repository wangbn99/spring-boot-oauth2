package com.comtwins.springboot.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Configuration
public class CacheConfig {

    @Bean
    public Cache<String, Entry<Object>> getCacheInstance() {
        return Caffeine.newBuilder()
                .expireAfterAccess(15, TimeUnit.MINUTES)
                .maximumSize(100)
                .build();
    }

    @Getter
    @Setter
    public static class Entry<T>{
        private T value;
        private Duration timeout;
        private long createAt = System.currentTimeMillis();

        public Entry(T value) {
            this(value, Duration.ofMinutes(10));
        }

        public Entry(T value, Duration timeout) {
            this.value = value;
            this.timeout = timeout;
        }
    }

};

