package io.cloudflight.keycloak.magiclink.sending;

import java.io.IOException;

import org.keycloak.common.util.ObjectUtil;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Sends the magic link by email to a raw address via the realm's configured
 * SMTP server. Uses the low-level {@link EmailSenderProvider} rather than the
 * user-centric template provider, so a link can be sent to an address that is
 * not (yet) a Keycloak user — which is what deferred provisioning needs.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class EmailLinkSender implements LinkSender {

    @Override
    public void sendLink(KeycloakSession session, String email, String link, String otpCode)
          throws IOException {
        RealmModel realm = session.getContext().getRealm();
        final String realmName =
              ObjectUtil.isBlank(realm.getDisplayName()) ? realm.getName() : realm.getDisplayName();

        String codeLineText = otpCode == null ? ""
              : "Or enter this code on the sign-in page: " + otpCode + "\n\n";
        String codeLineHtml = otpCode == null ? ""
              : "<p>Or enter this code on the sign-in page: <strong>" + escapeHtml(otpCode) + "</strong></p>";

        String subject = "Sign in to " + realmName;
        String text = "Click the link below to sign in to " + realmName + ":\n\n"
              + link + "\n\n"
              + codeLineText
              + "If you did not request this, you can safely ignore this email.";
        // The link/code are values we minted, but escape them (and the realm
        // name) for the HTML part as defence in depth.
        String html = "<p>Click the link below to sign in to " + escapeHtml(realmName) + ":</p>"
              + "<p><a href=\"" + escapeHtml(link) + "\">Sign in</a></p>"
              + codeLineHtml
              + "<p>If you did not request this, you can safely ignore this email.</p>";

        try {
            session.getProvider(EmailSenderProvider.class)
                  .send(realm.getSmtpConfig(), email, subject, text, html);
        } catch (EmailException e) {
            throw new IOException(e);
        }
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;")
              .replace("\"", "&quot;")
              .replace("'", "&#39;");
    }
}
