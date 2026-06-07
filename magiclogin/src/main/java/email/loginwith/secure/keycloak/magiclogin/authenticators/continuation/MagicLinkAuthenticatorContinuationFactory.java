package email.loginwith.secure.keycloak.magiclogin.authenticators.continuation;

import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

import email.loginwith.secure.keycloak.magiclogin.authenticators.AbstractMagicLinkAuthenticatorFactory;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkAuthenticatorContinuationFactory extends AbstractMagicLinkAuthenticatorFactory {

    private static final String PROVIDER_ID = "magiclink-continuation";

    private static final MagicLinkAuthenticatorContinuation INSTANCE = new MagicLinkAuthenticatorContinuation();


    @Override
    public String getDisplayType() {
        return "Magic Link Continuation";
    }

    @Override
    public String getHelpText() {
        return "Authenticator that sends a magic link which can be used to log in (continuation)";
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return INSTANCE;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
