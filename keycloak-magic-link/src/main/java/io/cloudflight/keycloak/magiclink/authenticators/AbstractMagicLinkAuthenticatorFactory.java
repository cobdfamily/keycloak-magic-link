package io.cloudflight.keycloak.magiclink.authenticators;

import static io.cloudflight.keycloak.magiclink.authenticators.MagicLinkValidityConstants.CREATE_USER_CONFIG_KEY;
import static io.cloudflight.keycloak.magiclink.authenticators.MagicLinkValidityConstants.DEFAULT_CREATE_USER;
import static io.cloudflight.keycloak.magiclink.authenticators.MagicLinkValidityConstants.DEFAULT_VALIDITY_IN_SECONDS;
import static io.cloudflight.keycloak.magiclink.authenticators.MagicLinkValidityConstants.VALIDITY_DURATION_CONFIG_KEY;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Common implementation for magic link authenticator factories.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public abstract class AbstractMagicLinkAuthenticatorFactory implements AuthenticatorFactory {

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty magicKeyValidityDuration = new ProviderConfigProperty();
        magicKeyValidityDuration.setName(VALIDITY_DURATION_CONFIG_KEY);
        magicKeyValidityDuration.setLabel("MagicKey Validity Duration in seconds");
        magicKeyValidityDuration.setType(ProviderConfigProperty.INTEGER_TYPE);
        magicKeyValidityDuration.setHelpText("Duration in seconds that a magic key is valid");
        magicKeyValidityDuration.setRequired(true);
        magicKeyValidityDuration.setDefaultValue(DEFAULT_VALIDITY_IN_SECONDS);

        ProviderConfigProperty createUser = new ProviderConfigProperty();
        createUser.setName(CREATE_USER_CONFIG_KEY);
        createUser.setLabel("Create user if not found");
        createUser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        createUser.setHelpText(
              "If enabled, a magic-link request for an email that matches no "
              + "existing user provisions that user just-in-time. The account's "
              + "email is marked verified once the magic link is clicked. When "
              + "disabled, unknown emails are ignored.");
        createUser.setDefaultValue(DEFAULT_CREATE_USER);

        return List.of(magicKeyValidityDuration, createUser);
    }

    @Override
    public void init(Config.Scope scope) {
        // not needed
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        // not needed
    }

    @Override
    public void close() {
        // not needed
    }

}
