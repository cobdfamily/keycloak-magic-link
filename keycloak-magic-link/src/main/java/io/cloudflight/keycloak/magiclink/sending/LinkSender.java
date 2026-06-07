package io.cloudflight.keycloak.magiclink.sending;

import java.io.IOException;

import org.keycloak.models.KeycloakSession;

/**
 * Abstraction to send magic links.
 * Usually, this is done via email, but alternative options might be implemented in the future.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public interface LinkSender {

    /**
     * Sends a given magic link to a given email address. The recipient need
     * not be an existing user (deferred provisioning creates the account only
     * once the link is validated).
     *
     * @param session       The Keycloak session
     * @param email         The recipient email address
     * @param link          The magic link
     * @param otpCode       Optional one-time code to include, or null to omit it
     * @param recipientName Optional display name for a greeting, or null
     * @throws IOException if the link was not sent successfully
     */
    void sendLink(KeycloakSession session, String email, String link, String otpCode, String recipientName)
          throws IOException;
}
