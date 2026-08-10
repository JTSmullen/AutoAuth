package com.autoauth.util;

import com.autoauth.model.AutoAuthUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;

public class AuthContext {

    /**
     *  Grabs user info from the JWT sent with the request
     *  <p>
     *      Use this method when you need the info from the jwt token, This info
     *      includes the User ID, User Roles and Custom Claims embedded within the
     *      JWT.
     *  </p>
     *
     *  <h2>Sub Methods:</h2>
     *  <ul>
     *      <li><b>Use {@link #getCurrentUserId()} if you only need the User ID.</b></li>
     *      <li><b>Use {@link #getCurrentUserRoles()} if you only need the User Roles.</b></li>
     *      <li><b>Use {@link #getCustomClaim(String)} if you only need the Users
     *      one specific custom claim.</b></li>
     *  </ul>
     *
     * @return Instance of {@link AutoAuthUser}, containing userID, user roles, and custom claims.
     * or {@link  Optional#empty()} if no user is currently authenticated.
     * @see AutoAuthUser
     * @since 1.0.0
     */
    public static Optional<AutoAuthUser> getCurrentUser() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof AutoAuthUser) {
            return Optional.of((AutoAuthUser) authentication.getPrincipal());
        }

        return Optional.empty();

    }

    /**
     * gets the current users ID.
     *
     * <p>
     *     This is a method for convenience to only retrieve the user ID
     *     See {@link #getCurrentUser()} for information about the other
     *     user data embedded in the JWT.
     * </p>
     *
     * @return the current users ID, or {@link Optional#empty()} if no user
     * is currently authenticated.
     */
    public static Optional<String> getCurrentUserId() {

        return getCurrentUser()
                .map(AutoAuthUser::userId);

    }

    /**
     * gets the current users Roles.
     *
     * <p>
     *     This is a method for convenience only to retrieve the users roles
     *     See {@link #getCurrentUser()} for information about the other user
     *     data embedded in the JWT.
     * </p>
     *
     * @return The current users Roles, or {@link Optional#empty()} if no
     * user is currently authenticated.
     */
    public static Optional<List<String>> getCurrentUserRoles(){
        return getCurrentUser()
                .map(AutoAuthUser::roles);
    }

    /**
     * gets the current users specific custom claim from the JWT
     *
     * <p>
     *     This is a method for convenience only to retrieve the specific
     *     custom claim of the user. See {@link #getCurrentUser()} for
     *     information about the other user data embedded in the JWT.
     * </p>
     *
     * @param claimKey the key of the custom claim you want to get
     *
     * @return the value of the custom claim, or {@link Optional#empty()} if the
     * user is not authenticated or the claim DNE.
     */
    public static Optional<Object> getCustomClaim(String claimKey) {
        return getCurrentUser()
                .map(user -> user.customClaims().get(claimKey));
    }

}