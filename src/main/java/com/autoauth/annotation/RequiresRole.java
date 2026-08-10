package com.autoauth.annotation;

import java.lang.annotation.*;

/**
 *  Enforces Role Based authentication on an endpoint
 *
 *  <p>
 *      Requests get tracked by client role. If a user is authenticated and has
 *      the proper roles the request will be allowed to go throw. The requests
 *      get tracked by their ({@code user:roles_"role"}). For requests that do
 *      not have the proper role, error code 403 FORBIDDEN. A role set higher
 *      than another, gives access to all endpoints the other role also has
 *      access.
 *  </p>
 *
 *  <h2>Usage Examples</h2>
 *
 *  Limits endpoints to proper roles in rbac
 *
 *  <pre>
 *      {@code
 *  @RequiresRole("admin")
 *  @GetMapping("/api/admin/dashboard")
 *  public String adminDashboard() {...}
 *  }
 *  </pre>
 *
 *  @see com.autoauth.filter.JwtAuthenticationFilter
 *  @since 1.0.0
 */

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresRole {

    String[] value();

    boolean requireAll() default false;

}