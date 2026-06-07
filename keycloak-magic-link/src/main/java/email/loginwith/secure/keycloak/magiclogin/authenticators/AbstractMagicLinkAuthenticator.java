package email.loginwith.secure.keycloak.magiclogin.authenticators;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.validation.Validation;

import email.loginwith.secure.keycloak.magiclogin.entity.MagicLinkSession;
import email.loginwith.secure.keycloak.magiclogin.sending.EmailLinkSender;
import email.loginwith.secure.keycloak.magiclogin.sending.LinkSender;
import email.loginwith.secure.keycloak.magiclogin.util.ValidationUtils;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.core.Response;

/**
 * Common implementation for magic link authenticators.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public abstract class AbstractMagicLinkAuthenticator implements MagicLinkAuthenticator {

    protected static final String EMAIL_INPUT_FORM_TEMPLATE = "email-login.ftl";
    protected static final String EMAIL_ATTRIBUTE_FORM_NAME = "username";

    protected static final String MAGICKEY_QUERY_PARAM = "magickey";
    protected static final String MAGICLINK_SESSION_ID_KEY = "magiclink-session-id";
    protected static final String OTP_FORM_PARAM = "code";
    protected static final String OTP_FORM_TEMPLATE = "otp-login.ftl";

    private final LinkSender linkSender = new EmailLinkSender();
    private static final Logger logger = Logger.getLogger(AbstractMagicLinkAuthenticator.class);


    @Override
    public void action(AuthenticationFlowContext context) {
        // A submitted one-time code takes precedence over the email form: the
        // OTP entry form posts the "code" field back to this same action.
        final String submittedCode =
              context.getHttpRequest().getDecodedFormParameters().getFirst(OTP_FORM_PARAM);
        if (submittedCode != null) {
            verifyOtp(context, submittedCode.trim());
            return;
        }

        // Get email from the submitted form
        final String email = getEmailAddressInput(context);
        if (ObjectUtil.isBlank(email)) {
            return;
        }
        processEmailAndSend(context, email);
    }

    /**
     * Send a magic link (and optional code) to the given email and challenge
     * the info/wait/code page. Shared by the form submission and the
     * login_hint shortcut. Does NOT create or set a user — the account is
     * created only when the link/code is validated (see resolveOrCreateUser).
     */
    protected void processEmailAndSend(AuthenticationFlowContext context, String email) {
        // Handle this address if it's an existing user, or — when JIT
        // provisioning is enabled — any syntactically valid email.
        UserModel existing = findUserByEmailAddress(context, email);
        boolean willHandle = existing != null
              || (isCreateUserEnabled(context) && Validation.isEmailValid(email));

        if (willHandle) {
            final String magicKey = generateMagicKey();
            final String magicLinkSessionId = UUID.randomUUID().toString();
            // Generate a one-time code only where it's usable (the normal,
            // same-device authenticator) and enabled.
            final String otp = (isOtpEnabled(context) && supportsOtp()) ? generateOtp() : null;
            storeMagicKey(context, magicKey, magicLinkSessionId, email, otp);
            // Personalise with the user's name only if one already exists; no
            // user is stubbed just for the greeting.
            final String recipientName = existing != null ? existing.getFirstName() : null;
            sendLink(context, email, getMagicLink(context, magicKey, magicLinkSessionId), otp, recipientName);
        }

        // Show the info/wait/code page regardless, so unknown (and
        // not-to-be-created) addresses cannot be enumerated from the response.
        showLinkSentInfo(context);
    }

    @Override
    public void sendLink(AuthenticationFlowContext context, String email, String magicLink) {
        sendLink(context, email, magicLink, null, null);
    }

    protected void sendLink(
          AuthenticationFlowContext context, String email, String magicLink,
          String otpCode, String recipientName) {
        try {
            linkSender.sendLink(context.getSession(), email, magicLink, otpCode, recipientName);
        } catch (IOException e) {
            logger.warn("MagicLink not generated", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, Response.serverError().build());
        }
    }

    /** Whether "skip email form when login_hint is present" is enabled. */
    protected boolean isSkipEmailWithLoginHintEnabled(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        return config != null && Boolean.parseBoolean(
              config.getConfig().get(MagicLinkValidityConstants.SKIP_EMAIL_WITH_LOGIN_HINT_CONFIG_KEY));
    }

    /**
     * If the skip-on-login-hint option is enabled and the auth session carries
     * a valid-email login_hint (forwarded by the RP / Keycloak broker), send
     * the link straight to it and challenge the wait/info page — skipping the
     * email entry form. Returns true when it handled the request.
     */
    protected boolean tryLoginHint(AuthenticationFlowContext context) {
        if (!isSkipEmailWithLoginHintEnabled(context)) {
            return false;
        }
        String hint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (ObjectUtil.isBlank(hint) || !Validation.isEmailValid(hint.trim())) {
            return false;
        }
        processEmailAndSend(context, hint.trim());
        return true;
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        // not needed
    }

    @Override
    public void close() {
        // not needed
    }


    protected abstract String getMagicLink(AuthenticationFlowContext context, String magicKey, String magicLinkSessionId);

    protected abstract void showLinkSentInfo(AuthenticationFlowContext context);


    protected String generateMagicKey() {
        return KeycloakModelUtils.generateId();
    }

    protected void storeMagicKey(
          AuthenticationFlowContext context, String magicKey, String magicLinkSessionId,
          String email, String otp) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        long validityDurationInSeconds = MagicLinkValidityConstants.DEFAULT_VALIDITY_IN_SECONDS;
        if (config != null) {
            validityDurationInSeconds = Integer.parseInt(config.getConfig().get(MagicLinkValidityConstants.VALIDITY_DURATION_CONFIG_KEY));
        }

        final long validTo = Time.currentTimeMillis() + validityDurationInSeconds * 1000L;

        MagicLinkSession magicLinkSession = new MagicLinkSession();
        magicLinkSession.setId(magicLinkSessionId);
        // Store only the hash of the key, never the key itself.
        magicLinkSession.setMagicKeyHash(ValidationUtils.sha256Hex(magicKey));
        magicLinkSession.setEmail(email);
        magicLinkSession.setValidTo(validTo);
        magicLinkSession.setRedirectUri(context.getRefreshUrl(true).toString());
        if (otp != null) {
            // Salt the OTP hash with the (random) session id so identical
            // codes across sessions don't share a hash.
            magicLinkSession.setOtpHash(otpHash(magicLinkSessionId, otp));
        }

        context.getAuthenticationSession().setAuthNote(MAGICLINK_SESSION_ID_KEY, magicLinkSessionId);
        getEntityManager(context).persist(magicLinkSession);
    }

    /**
     * Resolve the user for a validated magic link: an existing user by email,
     * or — when JIT provisioning is enabled and the address is a valid email —
     * a freshly-created one. Returns null when no user exists and creation is
     * not allowed (login then fails). Called only after ownership is proven.
     */
    protected UserModel resolveOrCreateUser(AuthenticationFlowContext context, String email) {
        UserModel user = findUserByEmailAddress(context, email);
        if (user == null && isCreateUserEnabled(context) && Validation.isEmailValid(email)) {
            user = createUser(context, email);
        }
        return user;
    }

    protected EntityManager getEntityManager(AuthenticationFlowContext context) {
        return context.getSession().getProvider(JpaConnectionProvider.class).getEntityManager();
    }

    protected Response getEmailLoginForm(AuthenticationFlowContext context) {
        return context.form()
              .setAttribute(EMAIL_ATTRIBUTE_FORM_NAME, "")
              .setAuthContext(null)
              .createForm(EMAIL_INPUT_FORM_TEMPLATE);
    }

    protected String getEmailAddressInput(AuthenticationFlowContext context) {
        String email = context.getHttpRequest().getDecodedFormParameters().getFirst(EMAIL_ATTRIBUTE_FORM_NAME).trim();

        if (ObjectUtil.isBlank(email)) {
            context.failure(AuthenticationFlowError.INVALID_USER,
                  context.form().setError("Email cannot be empty").createForm(EMAIL_INPUT_FORM_TEMPLATE));
            return null;
        }
        return email;
    }

    protected UserModel findUserByEmailAddress(AuthenticationFlowContext context, String email) {
        return KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), email);
    }

    // ---- one-time code (OTP) ------------------------------------------------

    /** Whether the "Also send a one-time code" flag is set on this execution. */
    protected boolean isOtpEnabled(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        return config != null
              && Boolean.parseBoolean(
                    config.getConfig().get(MagicLinkValidityConstants.SEND_OTP_CONFIG_KEY));
    }

    /**
     * Whether this authenticator can accept a typed code. Only the normal
     * (same-device) flavour does; continuation stays link-only.
     */
    protected boolean supportsOtp() {
        return false;
    }

    /** A fresh zero-padded numeric code (preserves leading zeros / fixed width). */
    protected String generateOtp() {
        int bound = (int) Math.pow(10, MagicLinkValidityConstants.OTP_LENGTH);
        int n = new SecureRandom().nextInt(bound);
        return String.format("%0" + MagicLinkValidityConstants.OTP_LENGTH + "d", n);
    }

    /** Salted SHA-256 of a code; the random session id is the salt. */
    protected String otpHash(String magicLinkSessionId, String code) {
        return ValidationUtils.sha256Hex(magicLinkSessionId + ":" + code);
    }

    /**
     * Verify a submitted one-time code against the current session. On success
     * the user is resolved/created (ownership is proven) and login completes;
     * on failure the wrong-attempt counter is charged and the session is burned
     * at {@link MagicLinkValidityConstants#MAX_OTP_ATTEMPTS}.
     */
    protected void verifyOtp(AuthenticationFlowContext context, String code) {
        final String sessionId = context.getAuthenticationSession().getAuthNote(MAGICLINK_SESSION_ID_KEY);
        final EntityManager em = getEntityManager(context);
        MagicLinkSession mls = sessionId == null ? null : em.find(MagicLinkSession.class, sessionId);

        if (mls == null || mls.getOtpHash() == null) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, buildOtpForm(context, true));
            return;
        }

        boolean expired = mls.getValidTo() < Time.currentTimeMillis();
        boolean matches = !ObjectUtil.isBlank(code)
              && ValidationUtils.constantTimeEquals(mls.getOtpHash(), otpHash(sessionId, code));

        if (!expired && matches) {
            final String email = mls.getEmail();
            removeMagicLinkSession(context, mls);  // single-use
            UserModel user = resolveOrCreateUser(context, email);
            if (user != null) {
                context.setUser(user);
                markEmailVerified(context);
                context.success();
                return;
            }
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, buildOtpForm(context, true));
            return;
        }

        // Wrong/expired code: charge an attempt; burn the session once the cap
        // is reached (or it has expired) so the low-entropy code can't be ground.
        if (expired || mls.getOtpAttempts() + 1 >= MagicLinkValidityConstants.MAX_OTP_ATTEMPTS) {
            removeMagicLinkSession(context, mls);
        } else {
            mls.setOtpAttempts(mls.getOtpAttempts() + 1);
            mergeMagicLinkSession(context, mls);
        }
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, buildOtpForm(context, true));
    }

    /** Render the code-entry form (optionally with an error). */
    protected Response buildOtpForm(AuthenticationFlowContext context, boolean error) {
        var form = context.form().setAuthContext(null);
        if (error) {
            form.setError("Invalid or expired code");
        }
        return form.createForm(OTP_FORM_TEMPLATE);
    }

    /**
     * Whether just-in-time user provisioning is enabled on this execution
     * (the "Create user if not found" config flag). Defaults to off.
     */
    protected boolean isCreateUserEnabled(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        return config != null
              && Boolean.parseBoolean(
                    config.getConfig().get(MagicLinkValidityConstants.CREATE_USER_CONFIG_KEY));
    }

    /**
     * Create a new enabled user keyed by the given email (username == email).
     * Email stays unverified until the magic link is clicked, at which point
     * {@link #markEmailVerified} flips it.
     */
    protected UserModel createUser(AuthenticationFlowContext context, String email) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = session.users().addUser(realm, email);
        user.setEnabled(true);
        user.setEmail(email);
        user.setEmailVerified(false);
        logger.infof("magic-link: provisioned new user for %s", email);
        return user;
    }

    /**
     * Mark the authenticated user's email as verified. Called on a successful
     * magic-link validation: clicking the emailed link proves ownership of the
     * address, so a just-provisioned (or previously unverified) user becomes
     * verified — avoiding a redundant VERIFY_EMAIL required action afterwards.
     */
    protected void markEmailVerified(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user != null && !user.isEmailVerified()) {
            user.setEmailVerified(true);
        }
    }

    protected void removeMagicLinkSession(AuthenticationFlowContext context, MagicLinkSession session) {
        EntityManager em = getEntityManager(context);
        em.getTransaction().begin();
        em.remove(session);
        em.getTransaction().commit();
    }

    protected void mergeMagicLinkSession(AuthenticationFlowContext context, MagicLinkSession session) {
        EntityManager em = getEntityManager(context);
        em.getTransaction().begin();
        em.merge(session);
        em.getTransaction().commit();
    }

}
