package email.loginwith.secure.keycloak.magiclogin.authenticators.continuation;

import email.loginwith.secure.keycloak.magiclogin.authenticators.AbstractMagicLoginAuthenticator;
import email.loginwith.secure.keycloak.magiclogin.entity.MagicLoginSession;
import email.loginwith.secure.keycloak.magiclogin.util.LinkUtils;
import jakarta.persistence.EntityManager;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Implementation of a "continuation" magic link authenticator
 * (see {@link email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLoginAuthenticator})
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLoginAuthenticatorContinuation extends AbstractMagicLoginAuthenticator {

    private static final String MAGICLOGIN_SESSION_ID_QUERY_PARAM = "id";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // The user is no longer pre-set (deferred provisioning); we're past
        // the initial email form once the session-id note exists.
        final String authNoteMagicLoginSessionId = context.getAuthenticationSession().getAuthNote(MAGICLOGIN_SESSION_ID_KEY);
        if (authNoteMagicLoginSessionId == null) {
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
        MagicLoginSession magicLoginSession = em.find(MagicLoginSession.class, authNoteMagicLoginSessionId);
        boolean loggedIn = magicLoginSession != null && magicLoginSession.isLoggedIn();
        String email = magicLoginSession != null ? magicLoginSession.getEmail() : null;

        // Ownership is proven only when the link has been clicked -> resolve or
        // create the user, then consume the session (single-use).
        UserModel user = loggedIn ? resolveOrCreateUser(context, email) : null;
        if (user != null) {
            removeMagicLoginSession(context, magicLoginSession);
            context.setUser(user);
            markEmailVerified(context);
            context.success();
        } else {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, getEmailLoginForm(context));
        }
    }

    @Override
    protected String getMagicLink(AuthenticationFlowContext context, String magicKey, String magicLoginSessionId) {
        return createMagicLogin(context, magicKey, magicLoginSessionId);
    }

    @Override
    protected void showLinkSentInfo(AuthenticationFlowContext context) {
        context.challenge(context.form().setAuthContext(null).createForm("wait-for-login.ftl"));
    }


    private String createMagicLogin(AuthenticationFlowContext context, String magicKey, String magicLoginSessionId) {
        String url = String.format("%s/realms/%s/%s",
                context.getSession().getContext().getUri().getBaseUri(),
                context.getRealm().getName(),
                Constants.MAGIC_LOGIN_PROVIDER_FACTORY_ID);
        return LinkUtils.getLink(url, Map.of(MAGICKEY_QUERY_PARAM, magicKey, MAGICLOGIN_SESSION_ID_QUERY_PARAM, magicLoginSessionId));
    }

}
