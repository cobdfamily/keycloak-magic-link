package email.loginwith.secure.keycloak.magiclogin.authenticators.continuation.api;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import email.loginwith.secure.keycloak.magiclogin.authenticators.continuation.Constants;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLoginContinuationRestResourceProviderFactory implements RealmResourceProviderFactory {

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new MagicLoginContinuationRestResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        //not needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        //not needed
    }

    @Override
    public void close() {
        //not needed
    }

    @Override
    public String getId() {
        return Constants.MAGIC_LOGIN_PROVIDER_FACTORY_ID;
    }
}
