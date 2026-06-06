package io.cloudflight.keycloak.magiclink.authenticators;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;

/**
 * Interface for authenticators that use magic links to log in users (passwordless).
 *
 * The typical flow for such an authenticator is:
 * 1) An email input form is shown.
 * 2) Users enter their email address and submit the form.
 * 3) A special ("magic") link is sent to their email address.
 * 4) They receive the email with the link, click on it and get authenticated.
 *
 * A magic link contains a "magic key" which acts as a one-time-password.
 *
 * Currently, there are two flavors of magic link authenticators: normal and continuation.
 * Normal: Users open the magic link in the same context (same browser) as the original login request.
 *         Then, the authenticated session continues in the browser/tab that opened after clicking the link.
 * Continuation: Users open the magic link in a different context (different browser/device) as the original login request.
 *               Then, the authenticated session continues in the original browser/tab that was used for the login
 *               request. Users get not authenticated in browser/tab that opened after clicking the link. This allows
 *               to log in on the desktop, but receive the email on a mobile device.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public interface MagicLinkAuthenticator extends Authenticator {

    /**
     * Sends a given magic link to the given email address. The recipient need
     * not be an existing user — with deferred provisioning the account is only
     * created once the link is validated.
     *
     * @param context   The keycloak context
     * @param email     The recipient email address
     * @param magicLink The link to send
     */
    void sendLink(AuthenticationFlowContext context, String email, String magicLink);
}
