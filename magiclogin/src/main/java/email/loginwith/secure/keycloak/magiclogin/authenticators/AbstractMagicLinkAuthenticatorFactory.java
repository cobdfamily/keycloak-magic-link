package email.loginwith.secure.keycloak.magiclogin.authenticators;

import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.CREATE_USER_CONFIG_KEY;
import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.DEFAULT_CREATE_USER;
import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.DEFAULT_SEND_OTP;
import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.DEFAULT_SKIP_EMAIL_WITH_LOGIN_HINT;
import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.DEFAULT_VALIDITY_IN_SECONDS;
import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.SEND_OTP_CONFIG_KEY;
import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.SKIP_EMAIL_WITH_LOGIN_HINT_CONFIG_KEY;
import static email.loginwith.secure.keycloak.magiclogin.authenticators.MagicLinkValidityConstants.VALIDITY_DURATION_CONFIG_KEY;

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

        ProviderConfigProperty sendOtp = new ProviderConfigProperty();
        sendOtp.setName(SEND_OTP_CONFIG_KEY);
        sendOtp.setLabel("Also send a one-time code");
        sendOtp.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        sendOtp.setHelpText(
              "If enabled, the email also contains a numeric one-time code and "
              + "the user can finish by typing it on the same device (an "
              + "alternative to clicking the link). Applies to the normal "
              + "magic-link authenticator.");
        sendOtp.setDefaultValue(DEFAULT_SEND_OTP);

        ProviderConfigProperty skipEmailWithLoginHint = new ProviderConfigProperty();
        skipEmailWithLoginHint.setName(SKIP_EMAIL_WITH_LOGIN_HINT_CONFIG_KEY);
        skipEmailWithLoginHint.setLabel("Skip email form when login_hint is present");
        skipEmailWithLoginHint.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        skipEmailWithLoginHint.setHelpText(
              "If enabled and the authentication request carries a valid-email "
              + "login_hint (forwarded by the relying party / Keycloak broker), "
              + "the email-entry form is skipped and the magic link is sent "
              + "straight to that address.");
        skipEmailWithLoginHint.setDefaultValue(DEFAULT_SKIP_EMAIL_WITH_LOGIN_HINT);

        return List.of(magicKeyValidityDuration, createUser, sendOtp, skipEmailWithLoginHint);
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
