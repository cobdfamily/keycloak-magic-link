package io.cloudflight.keycloak.magiclink.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Custom entity for storing magic link login request information.
 * This entity is used to check if the received magic key from the clicked magic link is valid.
 * It is created when the magic link is sent.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
@Entity
@Table(name = "MAGIC_LINK_SESSION")
public class MagicLinkSession {

    @Id
    @Column(name = "ID", length = 36, nullable = false)
    private String id;

    // SHA-256 hex of the magic key — the raw key is never persisted, so a
    // leaked DB row cannot be turned into a working link.
    @Column(name = "MAGIC_KEY", nullable = false)
    private String magicKeyHash;

    // Recipient address. With deferred provisioning the user may not exist
    // yet, so the email is carried here and the user is resolved/created
    // only when the link is validated (which proves ownership).
    @Column(name = "EMAIL")
    private String email;

    @Column(name = "VALID_TO", nullable = false)
    private long validTo;

    @Column(name = "LOGGED_IN", nullable = false)
    private boolean loggedIn = false;

    @Column(name = "REDIRECT_URI")
    private String redirectUri;


    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getMagicKeyHash() {
        return magicKeyHash;
    }

    public void setMagicKeyHash(String magicKeyHash) {
        this.magicKeyHash = magicKeyHash;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public long getValidTo() {
        return validTo;
    }

    public void setValidTo(long validTo) {
        this.validTo = validTo;
    }

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        this.loggedIn = loggedIn;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }
}
