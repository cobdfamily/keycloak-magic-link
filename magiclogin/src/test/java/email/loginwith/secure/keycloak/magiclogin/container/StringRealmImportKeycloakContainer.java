package email.loginwith.secure.keycloak.magiclogin.container;

import org.apache.commons.io.FilenameUtils;
import org.testcontainers.images.builder.Transferable;

import dasniko.testcontainers.keycloak.ExtendableKeycloakContainer;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class StringRealmImportKeycloakContainer extends ExtendableKeycloakContainer<StringRealmImportKeycloakContainer> {

    private static final String DEFAULT_REALM_IMPORT_FILES_LOCATION = "/opt/keycloak/data/import/";

    private String realmContent = null;


    public StringRealmImportKeycloakContainer() {
        super();
    }

    public StringRealmImportKeycloakContainer(String dockerImage) {
        super(dockerImage);
    }


    public StringRealmImportKeycloakContainer withRealmImportString(String realmContent) {
        this.realmContent = realmContent;
        return this;
    }


    @Override
    protected void configure() {
        super.configure();

        if (realmContent != null) {
            String realmFilename = "realm.json";
            String importFileInContainer = DEFAULT_REALM_IMPORT_FILES_LOCATION + FilenameUtils.getName(realmFilename);
            withCopyToContainer(Transferable.of(realmContent, 0644), importFileInContainer);
        }
    }
}
