package io.cloudflight.keycloak.magiclink.authenticators.normal;

import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.KeycloakUriBuilder;

import io.cloudflight.keycloak.magiclink.authenticators.AbstractMagicLinkAuthenticator;
import io.cloudflight.keycloak.magiclink.entity.MagicLinkSession;
import io.cloudflight.keycloak.magiclink.util.LinkUtils;
import io.cloudflight.keycloak.magiclink.util.ValidationUtils;
import jakarta.persistence.EntityManager;

/**
 * Implementation of a "normal" magic link authenticator
 * (see {@link io.cloudflight.keycloak.magiclink.authenticators.MagicLinkAuthenticator})
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkAuthenticatorNormal extends AbstractMagicLinkAuthenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (context.getUser() == null) {
            // We need the email address of the user
            context.challenge(getEmailLoginForm(context));
        } else {
            // User clicked on link -> validate magic key
            final String receivedMagicKey = context.getHttpRequest().getUri().getQueryParameters().getFirst(MAGICKEY_QUERY_PARAM);
            final String authNoteMagicLinkSessionId = context.getAuthenticationSession().getAuthNote(MAGICLINK_SESSION_ID_KEY);
            final EntityManager em = getEntityManager(context);

            MagicLinkSession magicLinkSession = em.find(MagicLinkSession.class, authNoteMagicLinkSessionId);
            boolean loggedIn = false;
            if (magicLinkSession != null) {
                loggedIn = ValidationUtils.isMagicLinkSessionValid(magicLinkSession, receivedMagicKey);
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
        return createMagicLink(context, magicKey);
    }

    @Override
    protected void showLinkSentInfo(AuthenticationFlowContext context) {
        context.challenge(context.form().setInfo("magiclink-emailSentText")
              // We reset the auth context here so that the entered username is not displayed on the link sent response page
              .setAuthContext(null)
              .createInfoPage());
    }


    private String createMagicLink(AuthenticationFlowContext context, String magicKey) {
        String url = KeycloakUriBuilder.fromUri(context.getRefreshExecutionUrl()).build().toString();
        return LinkUtils.getLink(url, Map.of(MAGICKEY_QUERY_PARAM, magicKey));
    }

}
