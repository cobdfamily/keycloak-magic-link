package email.loginwith.secure.keycloak.magiclogin.authenticators;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLoginValidityConstants {

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
    public static final String CREATE_USER_CONFIG_KEY = "magiclogin.create.user";

    /**
     * Default for {@link #CREATE_USER_CONFIG_KEY} — off, to preserve the
     * upstream "authenticate existing users only" behaviour.
     */
    public static final boolean DEFAULT_CREATE_USER = false;

    /**
     * Config key for emailing a one-time numeric code alongside the link, so
     * the user can finish on the same device by typing the code. Applies to
     * the normal (same-device) authenticator. Default off.
     */
    public static final String SEND_OTP_CONFIG_KEY = "magiclogin.send.otp";

    /** Default for {@link #SEND_OTP_CONFIG_KEY} — off. */
    public static final boolean DEFAULT_SEND_OTP = false;

    /** Number of digits in the one-time code. */
    public static final int OTP_LENGTH = 6;

    /**
     * Max wrong OTP attempts per magic-link session before it is burned. The
     * code is low-entropy (10^OTP_LENGTH), so this cap — together with the
     * validity window — is what makes brute force infeasible.
     */
    public static final int MAX_OTP_ATTEMPTS = 5;

    /**
     * Config key: when enabled and the auth request carries a valid-email
     * {@code login_hint}, the email-entry form is skipped and the link is sent
     * straight to the hinted address. Default off.
     */
    public static final String SKIP_EMAIL_WITH_LOGIN_HINT_CONFIG_KEY = "magiclogin.skip.email.with.login.hint";

    /** Default for {@link #SKIP_EMAIL_WITH_LOGIN_HINT_CONFIG_KEY} — off. */
    public static final boolean DEFAULT_SKIP_EMAIL_WITH_LOGIN_HINT = false;


    private MagicLoginValidityConstants() {
        //prevent instantiation
    }
}
