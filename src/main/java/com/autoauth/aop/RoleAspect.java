package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.util.AuthContext;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.access.AccessDeniedException;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

@Aspect
public class RoleAspect {

    @Before("@within(com.autoauth.processor.annotation.RequiresRole) " +
            "|| @annotation(com.autoauth.processor.annotation.RequiresRole)")
    public void checkRoles(JoinPoint joinPoint) {

        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        Class<?> targetClass = joinPoint.getTarget().getClass();

        RequiresRole annotation = AnnotatedElementUtils.findMergedAnnotation(method, RequiresRole.class);

        if(annotation == null) {
            annotation = AnnotatedElementUtils.findMergedAnnotation(targetClass, RequiresRole.class);
        }

        if (annotation != null) {
            validateRoles(annotation);
        }

    }

    private void validateRoles(RequiresRole requiresRole) {

        List<String> userRoles = AuthContext.getCurrentUser()
                .map(AutoAuthUser::roles)
                .orElse(List.of());

        List<String> requiredRoles = Arrays.asList(requiresRole.value());

        boolean hasAccess = false;

        if (requiresRole.requireAll()) {
            hasAccess = userRoles.containsAll(requiredRoles);
        } else {
            for (String role : requiredRoles) {
                if (userRoles.contains(role)) {
                    hasAccess = true;
                    break;
                }
            }
        }

        if (!hasAccess) {
            throw new AccessDeniedException("Access Denied: User lacks required role");
        }

    }

}