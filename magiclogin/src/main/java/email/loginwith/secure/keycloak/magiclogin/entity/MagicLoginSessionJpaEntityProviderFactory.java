package email.loginwith.secure.keycloak.magiclogin.entity;

import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLoginSessionJpaEntityProviderFactory implements JpaEntityProviderFactory {

    public static final String FACTORY_ID = "magiclogin-entity-provider-factory";

    private static final MagicLoginSessionJpaEntityProvider INSTANCE = new MagicLoginSessionJpaEntityProvider();


    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return INSTANCE;
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
        return FACTORY_ID;
    }
}
