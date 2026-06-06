package io.cloudflight.keycloak.magiclink.authenticators;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkValidityConstants {

    /**
     * The key of the keycloak config to set how long a magic key is valid.
     */
    public static final String VALIDITY_DURATION_CONFIG_KEY = "magickey.validity.duration";

    /**
     * The default validity duration in seconds.
     */
    public static final long DEFAULT_VALIDITY_IN_SECONDS = 5 * 60L;

    /**
     * Config key controlling just-in-time user provisioning. When enabled,
     * a magic-link request for an email that matches no existing user
     * creates that user (its email is marked verified once the link is
     * clicked). When disabled (default), unknown emails are ignored, as
     * upstream behaves.
     */
    public static final String CREATE_USER_CONFIG_KEY = "magiclink.create.user";

    /**
     * Default for {@link #CREATE_USER_CONFIG_KEY} — off, to preserve the
     * upstream "authenticate existing users only" behaviour.
     */
    public static final boolean DEFAULT_CREATE_USER = false;


    private MagicLinkValidityConstants() {
        //prevent instantiation
    }
}
