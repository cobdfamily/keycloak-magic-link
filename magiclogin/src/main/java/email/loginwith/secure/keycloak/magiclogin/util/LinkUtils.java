package email.loginwith.secure.keycloak.magiclogin.util;

import java.util.Map;
import java.util.StringJoiner;

/**
 * Utility class containing logic around links.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class LinkUtils {

    /**
     * Constructs a link from a given base url and optional query parameters.
     * Also ensures that there are no duplicate path separators (//) except after the protocol (e.g., "https://")
     *
     * @param url The base url
     * @param queryParams A map of query parameters (?key=value)
     * @return The resulting url
     */
    public static String getLink(String url, Map<String, String> queryParams) {
        final String prefix = url.contains("?") ? "&" : "?";
        StringJoiner queryString = new StringJoiner("&", prefix, "");
        if (queryParams != null) {
            queryParams.forEach((key, value) -> queryString.add(String.format("%s=%s", key, value)));
        }
        return String.format("%s%s", url, queryString).replaceAll("(?<!:)//+", "/");
    }


    private LinkUtils() {
        //prevent instantiation
    }
}
