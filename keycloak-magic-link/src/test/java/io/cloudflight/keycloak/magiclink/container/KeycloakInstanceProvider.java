package io.cloudflight.keycloak.magiclink.container;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class KeycloakInstanceProvider {

    // Pin tests to the official Keycloak image (quay.io/keycloak/keycloak)
    // at the same version the jar is built against. The version is passed
    // in from the keycloak.version pom property via surefire; the fallback
    // keeps IDE / no-property runs working.
    private static final String KEYCLOAK_IMAGE =
          "quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version", "26.6.3");

    private static final StringRealmImportKeycloakContainer keycloak =
          new StringRealmImportKeycloakContainer(KEYCLOAK_IMAGE)
                .withDefaultProviderClasses();


    public static void start() {
        start(null);
    }

    public static void start(String realmContent) {
        if (realmContent != null) {
            keycloak.withRealmImportString(realmContent);
        }
        keycloak.start();
    }

    public static void stop() {
        keycloak.close();
    }

    public static KeycloakInstanceInfo getInfo() {
        return new KeycloakInstanceInfo(
              keycloak.getAuthServerUrl()
        );
    }


    public record KeycloakInstanceInfo(
          String authServerUrl
    ) {

    }

}
