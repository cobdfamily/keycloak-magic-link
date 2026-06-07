package email.loginwith.secure.keycloak.magiclogin.authenticators.continuation.api;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkContinuationRestResourceProvider implements RealmResourceProvider {

    private KeycloakSession session;


    public MagicLinkContinuationRestResourceProvider(KeycloakSession session) {
        this.session = session;
    }


    @Override
    public Object getResource() {
        return new MagicLinkContinuationRestResource(session);
    }

    @Override
    public void close() {
        //not needed
    }
}
