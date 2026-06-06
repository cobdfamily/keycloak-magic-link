package io.cloudflight.keycloak.magiclink.authenticators;

import java.io.IOException;
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
import org.keycloak.services.validation.Validation;

import io.cloudflight.keycloak.magiclink.entity.MagicLinkSession;
import io.cloudflight.keycloak.magiclink.sending.EmailLinkSender;
import io.cloudflight.keycloak.magiclink.sending.LinkSender;
import io.cloudflight.keycloak.magiclink.util.ValidationUtils;
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

    private final LinkSender linkSender = new EmailLinkSender();
    private static final Logger logger = Logger.getLogger(AbstractMagicLinkAuthenticator.class);


    @Override
    public void action(AuthenticationFlowContext context) {
        // Get email from the submitted form
        final String email = getEmailAddressInput(context);
        if (ObjectUtil.isBlank(email)) {
            return;
        }

        // Decide whether to handle this address: an existing user, or — when
        // JIT provisioning is enabled — any syntactically valid email. We do
        // NOT create or set the user here: the account is created only when
        // the link is validated (proving ownership). See resolveOrCreateUser,
        // called from the concrete authenticators' success path.
        boolean willHandle = findUserByEmailAddress(context, email) != null
              || (isCreateUserEnabled(context) && Validation.isEmailValid(email));

        if (willHandle) {
            final String magicKey = generateMagicKey();
            final String magicLinkSessionId = UUID.randomUUID().toString();
            storeMagicKey(context, magicKey, magicLinkSessionId, email);
            sendLink(context, email, getMagicLink(context, magicKey, magicLinkSessionId));
        }

        // Show the info/wait page regardless, so unknown (and not-to-be-created)
        // addresses cannot be enumerated from the response.
        showLinkSentInfo(context);
    }

    @Override
    public void sendLink(AuthenticationFlowContext context, String email, String magicLink) {
        try {
            linkSender.sendLink(context.getSession(), email, magicLink);
        } catch (IOException e) {
            logger.warn("MagicLink not generated", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, Response.serverError().build());
        }
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
          AuthenticationFlowContext context, String magicKey, String magicLinkSessionId, String email) {
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

}
