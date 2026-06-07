package email.loginwith.secure.keycloak.magiclogin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.microsoft.playwright.options.LoadState;

import email.loginwith.secure.keycloak.magiclogin.container.KeycloakInstanceProvider;
import email.loginwith.secure.keycloak.magiclogin.util.RealmTemplate;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
class MagicLinkNormalTest extends AbstractMagicLinkBaseTest {

    private static final String REALM_TEMPLATE = "magiclink-normal.json.j2";


    @Test
    @RealmTemplate(REALM_TEMPLATE)
    void testEmailSent() {
        KeycloakInstanceProvider.KeycloakInstanceInfo info = KeycloakInstanceProvider.getInfo();

        loginWithEmailAddress(info.authServerUrl(), "admin1@example.org");
        Email email = receiveEmail(1, 0);

        assertNotNull(email);
        assertEquals("keycloak@example.org", email.from());
        assertEquals("admin1@example.org", email.to());
        assertEquals("Login to Keycloak", email.subject());

        assertNotNull(email.link());
        assertTrue(email.bodyTxt().contains(email.link()));
        assertTrue(email.bodyHtml().contains(email.link()));
    }

    @Test
    @RealmTemplate(REALM_TEMPLATE)
    void testLoginSuccessful() {
        KeycloakInstanceProvider.KeycloakInstanceInfo info = KeycloakInstanceProvider.getInfo();

        loginWithEmailAddress(info.authServerUrl(), "admin1@example.org");
        Email email = receiveEmail(1, 0);

        assertNotNull(email);
        assertNotNull(email.link());

        String response = openLink(email.link());
        assertLogin(response, true);
    }

    @Test
    @RealmTemplate(REALM_TEMPLATE)
    void testLoginWrongUser() {
        KeycloakInstanceProvider.KeycloakInstanceInfo info = KeycloakInstanceProvider.getInfo();

        loginWithEmailAddress(info.authServerUrl(), "invalid@example.org");
        Email email = receiveEmail(0, 0);
        assertNull(email);

        String response = openLink(info.authServerUrl());
        assertLogin(response, false);
    }

    @Test
    @RealmTemplate(REALM_TEMPLATE)
    void testLoginLinkOnlyValidOnce() {
        KeycloakInstanceProvider.KeycloakInstanceInfo info = KeycloakInstanceProvider.getInfo();

        loginWithEmailAddress(info.authServerUrl(), "admin1@example.org");
        Email email = receiveEmail(1, 0);
        assertNotNull(email);

        String response = openLink(email.link());
        assertLogin(response, true);

        logout();

        //try logging in again
        response = openLink(email.link());
        assertLogin(response, false);
    }


    @Test
    @RealmTemplate("magiclink-normal-jit.json.j2")
    void testNewUserProvisionedOnLinkClick() {
        KeycloakInstanceProvider.KeycloakInstanceInfo info = KeycloakInstanceProvider.getInfo();

        // Brand-new email that is not a user yet; with "Create user if not
        // found" enabled, the link is sent and the account is created only
        // when the link is clicked (deferred provisioning).
        loginWithEmailAddress(info.authServerUrl(), "brand-new-user@example.org");
        Email email = receiveEmail(1, 0);
        assertNotNull(email);
        assertNotNull(email.link());

        String response = openLink(email.link());
        assertLogin(response, true);
    }

    @Test
    @RealmTemplate("magiclink-normal-otp.json.j2")
    void testOtpLogin() {
        KeycloakInstanceProvider.KeycloakInstanceInfo info = KeycloakInstanceProvider.getInfo();

        loginWithEmailAddress(info.authServerUrl(), "otp-user@example.org");
        Email email = receiveEmail(1, 0);
        assertNotNull(email);

        // The email carries a one-time code; type it into the code form that
        // is now shown on the original page (an alternative to the link).
        String code = extractOtp(email.bodyTxt());
        assertNotNull(code, "no OTP code found in email body");
        page.locator("#code").fill(code);
        page.locator("[type=submit]").click();
        page.waitForLoadState(LoadState.NETWORKIDLE);

        assertLogin(page.content(), true);
    }

    private static String extractOtp(String emailBody) {
        Matcher m = Pattern.compile("enter this code on the sign-in page:\\s*(\\d{6})").matcher(emailBody);
        return m.find() ? m.group(1) : null;
    }


    //This test is currently disabled until we find a way to manipulate time in keycloak.
    @Disabled
    @Test
    @RealmTemplate(REALM_TEMPLATE)
    void testLinkExpiry() {
        KeycloakInstanceProvider.KeycloakInstanceInfo info = KeycloakInstanceProvider.getInfo();

        loginWithEmailAddress(info.authServerUrl(), "admin1@example.org");

        //TODO manipulate time such that the subsequent login attempt fails because the magic link is already expired

        Email email = receiveEmail(1, 0);
        assertNotNull(email);

        String response = openLink(email.link());
        assertLogin(response, false);
    }


    private void assertLogin(String response, boolean successful) {
        // On success the magic-link flow completes and lands on an
        // authenticated Keycloak console SPA; on failure the login form (or an
        // error) is shown instead. The admin-console shell title is only
        // reached after authentication.
        boolean actual = response.contains("Keycloak Administration Console");
        assertEquals(successful, actual);
    }

}
