package io.cloudflight.keycloak.magiclink.sending;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import org.keycloak.common.util.ObjectUtil;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.theme.Theme;
import org.keycloak.theme.beans.MessageFormatterMethod;
import org.keycloak.theme.freemarker.FreeMarkerProvider;

/**
 * Sends the magic-link email by rendering the theme's FreeMarker email
 * templates ({@code text/magiclink-email.ftl} / {@code html/magiclink-email.ftl})
 * and delivering them to a raw address via {@link EmailSenderProvider}.
 *
 * Crucially this does NOT depend on a {@link org.keycloak.models.UserModel}:
 * the templates are rendered from a plain attribute map, so a link can be sent
 * to an address that is not (yet) a Keycloak user — which deferred provisioning
 * requires. When the caller already knows the recipient's name (an existing
 * user was found) it may pass {@code recipientName} for a friendlier greeting;
 * no fake user is constructed just to personalise the email.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class EmailLinkSender implements LinkSender {

    private static final String TEXT_TEMPLATE = "text/magiclink-email.ftl";
    private static final String HTML_TEMPLATE = "html/magiclink-email.ftl";
    private static final String SUBJECT_KEY = "magiclink-emailSubject";

    @Override
    public void sendLink(
          KeycloakSession session, String email, String link, String otpCode, String recipientName)
          throws IOException {
        RealmModel realm = session.getContext().getRealm();
        final String realmName =
              ObjectUtil.isBlank(realm.getDisplayName()) ? realm.getName() : realm.getDisplayName();
        final Locale locale = resolveLocale(realm);

        try {
            Theme theme = session.theme().getTheme(Theme.Type.EMAIL);
            Properties messages = theme.getMessages(locale);

            Map<String, Object> model = new HashMap<>();
            model.put("link", link);
            model.put("realmName", realmName);
            model.put("locale", locale.toLanguageTag());
            model.put("msg", new MessageFormatterMethod(locale, messages));
            if (otpCode != null) {
                model.put("otpCode", otpCode);
            }
            if (!ObjectUtil.isBlank(recipientName)) {
                model.put("name", recipientName);
            }

            FreeMarkerProvider freeMarker = session.getProvider(FreeMarkerProvider.class);
            String text = freeMarker.processTemplate(model, TEXT_TEMPLATE, theme);
            String html = freeMarker.processTemplate(model, HTML_TEMPLATE, theme);
            String subject = formatSubject(messages, realmName);

            session.getProvider(EmailSenderProvider.class)
                  .send(realm.getSmtpConfig(), email, subject, text, html);
        } catch (EmailException e) {
            throw new IOException(e);
        } catch (Exception e) {
            // Theme/FreeMarker errors etc. — surface as IOException so the
            // authenticator reports an internal error rather than leaking.
            throw new IOException("Failed to render/send magic-link email", e);
        }
    }

    private static Locale resolveLocale(RealmModel realm) {
        String def = realm.getDefaultLocale();
        return ObjectUtil.isBlank(def) ? Locale.ENGLISH : Locale.forLanguageTag(def);
    }

    private static String formatSubject(Properties messages, String realmName) {
        String pattern = messages.getProperty(SUBJECT_KEY, "Login to {0}");
        return new MessageFormat(pattern, Locale.ENGLISH).format(new Object[] {realmName});
    }
}
