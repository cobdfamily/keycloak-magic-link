package email.loginwith.secure.keycloak.magiclogin.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import com.hubspot.jinjava.Jinjava;

import email.loginwith.secure.keycloak.magiclogin.container.KeycloakInstanceProvider;
import email.loginwith.secure.keycloak.magiclogin.container.MailhogInstanceProvider;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class KeycloakRealmTemplateExtension implements BeforeEachCallback {

    private static final Path REALM_TEMPLATE_DIR = Paths.get("src", "test", "resources", "templates", "realms");


    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        if (context.getTestMethod().isPresent()) {
            RealmTemplate realmTemplate = context.getTestMethod().get().getAnnotation(RealmTemplate.class);
            if (realmTemplate != null) {
                Path templateFile = REALM_TEMPLATE_DIR.resolve(realmTemplate.value());
                KeycloakInstanceProvider.start(getRenderedTemplate(templateFile, getRealmVariables()));
            } else {
                KeycloakInstanceProvider.start(null);
            }
        }
    }


    private String getRenderedTemplate(Path templateFile, Map<String, Object> variables) throws IOException {
        Jinjava jinjava = new Jinjava();
        String template = Files.readString(templateFile, StandardCharsets.UTF_8);
        return jinjava.render(template, variables);
    }

    private Map<String, Object> getRealmVariables() {
        return Map.of("smtp_port", MailhogInstanceProvider.getInfo().smtpPort());
    }

}
