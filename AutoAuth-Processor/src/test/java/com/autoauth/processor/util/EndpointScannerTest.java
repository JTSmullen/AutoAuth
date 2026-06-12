package com.autoauth.processor.util;

import com.autoauth.processor.annotation.PublicEndpoint;
import com.autoauth.processor.util.EndpointScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class EndpointScannerTest {

    private ApplicationContext mockContext;
    private EndpointScanner scanner;

    @BeforeEach
    void setUp() {
        mockContext = Mockito.mock(ApplicationContext.class);
        scanner = new EndpointScanner(mockContext);
    }

    @Test
    void shouldExtractAllPathsWhenEntireControllerIsPublic() {
        when(mockContext.getBeanNamesForAnnotation(org.springframework.stereotype.Controller.class))
                .thenReturn(new String[]{"publicController"});

        doReturnClass(PublicController.class, "publicController");

        List<String> paths = scanner.getPublicPaths();

        assertEquals(1, paths.size());
        assertTrue(paths.contains("/api/public/**"));
    }

    @Test
    void shouldExtractOnlyAnnotatedMethodsWhenClassIsNotPublic() {
        when(mockContext.getBeanNamesForAnnotation(org.springframework.stereotype.Controller.class))
                .thenReturn(new String[]{"mixedController"});

        doReturnClass(MixedController.class, "mixedController");

        List<String> paths = scanner.getPublicPaths();

        assertEquals(1, paths.size());
        assertTrue(paths.contains("/api/mixed/public-method"));
        assertFalse(paths.contains("/api/mixed/secured-method"));
    }

    @SuppressWarnings("unchecked")
    private void doReturnClass(Class<?> clazz, String beanName) {
        when(mockContext.getType(beanName)).thenAnswer(invocation -> clazz);
    }

    @RestController
    @RequestMapping("/api/public")
    @PublicEndpoint
    static class PublicController {
        @GetMapping("/one") public String one() { return ""; }
        @GetMapping("/two") public String two() { return ""; }
    }

    @RestController
    @RequestMapping("/api/mixed")
    static class MixedController {

        @PublicEndpoint
        @GetMapping("/public-method")
        public String pub() { return ""; }

        @GetMapping("/secured-method")
        public String sec() { return ""; }
    }
}