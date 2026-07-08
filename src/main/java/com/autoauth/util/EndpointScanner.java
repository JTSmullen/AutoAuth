package com.autoauth.util;

import com.autoauth.annotation.PublicEndpoint;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class EndpointScanner {

    private final ApplicationContext applicationContext;

    public EndpointScanner(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public List<String> getPublicPaths() {

        List<String> publicPaths = new ArrayList<>();

        String[] beanNames = applicationContext.getBeanNamesForAnnotation(Controller.class);

        for (String beanName : beanNames) {

            Class<?> beanType = applicationContext.getType(beanName);
            if (beanType == null) continue;

            RequestMapping classMapping = AnnotatedElementUtils.findMergedAnnotation(beanType, RequestMapping.class);
            String[] basePaths = (classMapping != null && classMapping.value().length > 0)
                    ? classMapping.value()
                    : new String[]{""};

            boolean isClassPublic = AnnotatedElementUtils.hasAnnotation(beanType, PublicEndpoint.class);

            if (isClassPublic) {

                for (String basePath : basePaths) {
                    publicPaths.add(cleanPath(basePath + "/**"));
                }

                continue;

            }

            for (Method method : beanType.getDeclaredMethods()) {

                if (AnnotatedElementUtils.hasAnnotation(method, PublicEndpoint.class)) {

                    RequestMapping methodMapping = AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);

                    if (methodMapping != null && methodMapping.value().length > 0) {

                        for (String basePath : basePaths) {
                            for (String methodPath : methodMapping.value()) {
                                publicPaths.add(cleanPath(basePath + methodPath));
                            }
                        }

                    } else {

                        for (String basePath : basePaths) {
                            publicPaths.add(cleanPath(basePath));
                        }

                    }

                }

            }

        }

        return publicPaths;

    }

    private String cleanPath(String path) {
        return path.replaceAll("//+", "/");
    }

}