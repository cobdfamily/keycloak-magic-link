package email.loginwith.secure.keycloak.magiclogin.authenticators.continuation;

import email.loginwith.secure.keycloak.magiclogin.authenticators.AbstractMagicLinkAuthenticator;
import email.loginwith.secure.keycloak.magiclogin.entity.MagicLinkSession;
import email.loginwith.secure.keycloak.magiclogin.util.LinkUtils;
import jakarta.persistence.EntityManager;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Implementation of a "continuation" magic link authenticator
 * (see {@link email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkAuthenticator})
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkAuthenticatorContinuation extends AbstractMagicLinkAuthenticator {

    private static final String MAGICLINK_SESSION_ID_QUERY_PARAM = "id";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // The user is no longer pre-set (deferred provisioning); we're past
        // the initial email form once the session-id note exists.
        final String authNoteMagicLinkSessionId = context.getAuthenticationSession().getAuthNote(MAGICLINK_SESSION_ID_KEY);
        if (authNoteMagicLinkSessionId == null) {
            // Initial entry. If a login_hint is present and the option is on,
            // skip the email form and send straight to the hinted address.
            if (tryLoginHint(context)) {
                return;
            }
            // Otherwise ask for the email address.
            context.challenge(getEmailLoginForm(context));
            return;
        }

        // Waiting for the magic link to be clicked (on any device); the REST
        // resource flips loggedIn once it validates the key.
        final EntityManager em = getEntityManager(context);
        MagicLinkSession magicLinkSession = em.find(MagicLinkSession.class, authNoteMagicLinkSessionId);
        boolean loggedIn = magicLinkSession != null && magicLinkSession.isLoggedIn();
        String email = magicLinkSession != null ? magicLinkSession.getEmail() : null;

        // Ownership is proven only when the link has been clicked -> resolve or
        // create the user, then consume the session (single-use).
        UserModel user = loggedIn ? resolveOrCreateUser(context, email) : null;
        if (user != null) {
            removeMagicLinkSession(context, magicLinkSession);
            context.setUser(user);
            markEmailVerified(context);
            context.success();
        } else {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, getEmailLoginForm(context));
        }
    }

    @Override
    protected String getMagicLink(AuthenticationFlowContext context, String magicKey, String magicLinkSessionId) {
        return createMagicLink(context, magicKey, magicLinkSessionId);
    }

    @Override
    protected void showLinkSentInfo(AuthenticationFlowContext context) {
        context.challenge(context.form().setAuthContext(null).createForm("wait-for-login.ftl"));
    }


    private String createMagicLink(AuthenticationFlowContext context, String magicKey, String magicLinkSessionId) {
        String url = String.format("%s/realms/%s/%s",
                context.getSession().getContext().getUri().getBaseUri(),
                context.getRealm().getName(),
                Constants.MAGIC_LINK_PROVIDER_FACTORY_ID);
        return LinkUtils.getLink(url, Map.of(MAGICKEY_QUERY_PARAM, magicKey, MAGICLINK_SESSION_ID_QUERY_PARAM, magicLinkSessionId));
    }

}
