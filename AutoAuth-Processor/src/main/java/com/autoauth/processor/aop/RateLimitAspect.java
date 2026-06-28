package com.autoauth.processor.aop;

import com.autoauth.processor.annotation.RateLimit;
import com.autoauth.processor.ratelimit.RateLimitService;
import com.autoauth.processor.util.AuthContext;
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
import java.util.Optional;

@Aspect
public class RateLimitAspect {

    private final RateLimitService rateLimitService;

    public RateLimitAspect(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    @Before("@within(com.autoauth.processor.annotation.RateLimit) || @annotation(com.autoauth.processor.annotation.RateLimit)")
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

        if (userId.isPresent()) {
            callerKey = "user:" + userId;
        } else {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                callerKey = "ip:" + request.getRemoteAddr();
            } else {
                callerKey = "ip:unknown";
            }
        }

        // 2. Build a unique cache key (e.g., "user:user_99:searchMethod")
        String cacheKey = callerKey + ":" + methodName;
        long windowMillis = rateLimit.unit().toMillis(rateLimit.window());

        // 3. Check with the RateLimitService
        boolean allowed = rateLimitService.isAllowed(cacheKey, rateLimit.requests(), windowMillis);

        // 4. Reject with HTTP 429 Too Many Requests if they exceed the limit
        if (!allowed) {
            throw new ResponseStatusException(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Rate limit exceeded. Please try again later."
            );
        }
    }
}