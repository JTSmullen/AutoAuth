package com.autoauth.aop;

import com.autoauth.annotation.RateLimit;
import com.autoauth.annotation.UserQuota;
import com.autoauth.exception.RateLimitExceededException;
import com.autoauth.ratelimit.RateLimitService;
import com.autoauth.util.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

@Aspect
public class RateLimitAspect {

    private final RateLimitService rateLimitService;

    public RateLimitAspect(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    @Before("@within(com.autoauth.annotation.RateLimit) || @annotation(com.autoauth.annotation.RateLimit)")
    public void checkRateLimit(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Class<?> targetClass = joinPoint.getTarget().getClass();

        RateLimit annotation = AnnotatedElementUtils.findMergedAnnotation(method, RateLimit.class);
        if (annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(targetClass, RateLimit.class);
        }

        if (annotation != null) {
            enforceLimit(annotation, method.getName());
        }
    }

    private void enforceLimit(RateLimit rateLimit, String methodName) {
        String callerKey;
        Optional<String> userId = AuthContext.getCurrentUserId();

        int maxRequests = rateLimit.fallbackRequests();

        if (userId.isPresent()) {
            callerKey = "user:" + userId.get();

            Optional<List<String>> userRoles = AuthContext.getCurrentUserRoles();

            OptionalInt highestLimit = Arrays.stream(rateLimit.value())
                    .filter(quota -> userRoles.get().stream()
                            .anyMatch(role -> role.equalsIgnoreCase(quota.role())))
                    .mapToInt(UserQuota::maxRequests)
                    .max();

            if (highestLimit.isPresent()) {
                maxRequests = highestLimit.getAsInt();
            }
        } else {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                callerKey = "ip:" + request.getRemoteAddr();
            } else {
                callerKey = "ip:unknown";
            }
        }

        String cacheKey = callerKey + ":" + methodName;
        long windowMillis = rateLimit.unit().toMillis(rateLimit.window());

        boolean allowed = rateLimitService.isAllowed(cacheKey, maxRequests, windowMillis);

        if (!allowed) {
            throw new RateLimitExceededException("Rate Limit Exceeded. Please try again later.");
        }
    }
}