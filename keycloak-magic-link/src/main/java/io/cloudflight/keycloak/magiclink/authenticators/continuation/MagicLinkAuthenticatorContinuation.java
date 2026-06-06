package io.cloudflight.keycloak.magiclink.authenticators.continuation;

import io.cloudflight.keycloak.magiclink.authenticators.AbstractMagicLinkAuthenticator;
import io.cloudflight.keycloak.magiclink.entity.MagicLinkSession;
import io.cloudflight.keycloak.magiclink.util.LinkUtils;
import jakarta.persistence.EntityManager;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;

import java.util.Map;

/**
 * Implementation of a "continuation" magic link authenticator
 * (see {@link io.cloudflight.keycloak.magiclink.authenticators.MagicLinkAuthenticator})
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkAuthenticatorContinuation extends AbstractMagicLinkAuthenticator {

    private static final String MAGICLINK_SESSION_ID_QUERY_PARAM = "id";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (context.getUser() == null) {
            // We need the email address of the user
            context.challenge(getEmailLoginForm(context));
        } else {
            // We wait for the magic link to be clicked
            final String authNoteMagicLinkSessionId = context.getAuthenticationSession().getAuthNote(MAGICLINK_SESSION_ID_KEY);
            final EntityManager em = getEntityManager(context);
            MagicLinkSession magicLinkSession = em.find(MagicLinkSession.class, authNoteMagicLinkSessionId);
            boolean loggedIn = false;
            if (magicLinkSession != null && magicLinkSession.isLoggedIn()) {
                loggedIn = true;
                removeMagicLinkSession(context, magicLinkSession);
            }

            if (loggedIn) {
                markEmailVerified(context);
                context.success();
            } else {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, getEmailLoginForm(context));
            }
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
