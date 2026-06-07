package email.loginwith.secure.keycloak.magiclogin.authenticators.normal;

import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.models.UserModel;

import email.loginwith.secure.keycloak.magiclogin.authenticators.AbstractMagicLinkAuthenticator;
import email.loginwith.secure.keycloak.magiclogin.entity.MagicLinkSession;
import email.loginwith.secure.keycloak.magiclogin.util.LinkUtils;
import email.loginwith.secure.keycloak.magiclogin.util.ValidationUtils;
import jakarta.persistence.EntityManager;

/**
 * Implementation of a "normal" magic link authenticator
 * (see {@link email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkAuthenticator})
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkAuthenticatorNormal extends AbstractMagicLinkAuthenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        final String receivedMagicKey = context.getHttpRequest().getUri().getQueryParameters().getFirst(MAGICKEY_QUERY_PARAM);
        if (receivedMagicKey == null) {
            // Initial entry. If a login_hint is present and the option is on,
            // skip the email form and send straight to the hinted address.
            if (tryLoginHint(context)) {
                return;
            }
            // Otherwise ask for the email address. The user is no longer
            // pre-set (deferred provisioning), so we detect the link click by
            // the presence of the magickey query param rather than by getUser().
            context.challenge(getEmailLoginForm(context));
            return;
        }

        // Link clicked -> validate the magic key against the stored session.
        final String authNoteMagicLinkSessionId = context.getAuthenticationSession().getAuthNote(MAGICLINK_SESSION_ID_KEY);
        final EntityManager em = getEntityManager(context);

        MagicLinkSession magicLinkSession = em.find(MagicLinkSession.class, authNoteMagicLinkSessionId);
        boolean valid = ValidationUtils.isMagicLinkSessionValid(magicLinkSession, receivedMagicKey);
        String email = magicLinkSession != null ? magicLinkSession.getEmail() : null;
        if (magicLinkSession != null) {
            // Single-use: consume the session whether or not it validated.
            removeMagicLinkSession(context, magicLinkSession);
        }

        // Ownership is proven only now -> resolve or create the user.
        UserModel user = valid ? resolveOrCreateUser(context, email) : null;
        if (user != null) {
            context.setUser(user);
            markEmailVerified(context);
            context.success();
        } else {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, getEmailLoginForm(context));
        }
    }

    @Override
    protected String getMagicLink(AuthenticationFlowContext context, String magicKey, String magicLinkSessionId) {
        return createMagicLink(context, magicKey);
    }

    @Override
    protected boolean supportsOtp() {
        return true;
    }

    @Override
    protected void showLinkSentInfo(AuthenticationFlowContext context) {
        if (isOtpEnabled(context)) {
            // Offer a code-entry form (the email also carries the code) as a
            // same-device alternative to clicking the link.
            context.challenge(buildOtpForm(context, false));
            return;
        }
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
