package io.cloudflight.keycloak.magiclink.util;

import io.cloudflight.keycloak.magiclink.entity.MagicLinkSession;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.common.util.Time;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

/**
 * Utility class containing logic around validation of input/magic keys.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class ValidationUtils {

    private static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");


    /**
     * Checks if the given received magic key is valid for the given session.
     *
     * @param session          The session (was stored when the magic link is sent)
     * @param receivedMagicKey The magic key received when the user clicked the magic link
     * @return true if the magic key is valid, false otherwise
     */
    public static boolean isMagicLinkSessionValid(MagicLinkSession session, String receivedMagicKey) {
        if (session == null || ObjectUtil.isBlank(receivedMagicKey)) {
            return false;
        }

        // The session stores only the SHA-256 of the magic key; hash the
        // received key and compare in constant time so neither a DB leak
        // nor a timing side-channel exposes a usable key.
        if (!constantTimeEquals(session.getMagicKeyHash(), sha256Hex(receivedMagicKey))) {
            return false;
        }

        if (session.getValidTo() < Time.currentTimeMillis()) {
            return false;
        }

        return true;
    }

    /**
     * SHA-256 of the input, lower-case hex. Used to store/compare magic keys
     * and OTP codes without keeping the raw secret.
     */
    public static String sha256Hex(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                  .digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by every JVM; this cannot happen.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Constant-time string comparison (avoids leaking match length/position
     * via timing). Null-safe: a null operand is never equal.
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
              a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Checks if a given input string is a valid UUID.
     * Used for validating input.
     *
     * @param input The input string
     * @return true if the input string is a valid UUID, false otherwise
     */
    public static boolean isUUID(String input) {
        return !ObjectUtil.isBlank(input) && UUID_PATTERN.matcher(input).matches();
    }


    private ValidationUtils() {
        //prevent instantiation
    }

}
