package email.loginwith.secure.keycloak.magiclogin.entity;

import java.util.Collections;
import java.util.List;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLoginSessionJpaEntityProvider implements JpaEntityProvider {
    @Override
    public List<Class<?>> getEntities() {
        return Collections.singletonList(MagicLoginSession.class);
    }

    @Override
    public String getChangelogLocation() {
        return "META-INF/liquibase/magiclogin_session_changelog.xml";
    }

    @Override
    public String getFactoryId() {
        return MagicLoginSessionJpaEntityProviderFactory.FACTORY_ID;
    }

    @Override
    public void close() {
        //not needed
    }
}
