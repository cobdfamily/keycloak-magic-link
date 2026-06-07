package email.loginwith.secure.keycloak.magiclogin.authenticators.continuation.api;

import email.loginwith.secure.keycloak.magiclogin.authenticators.continuation.Constants;
import email.loginwith.secure.keycloak.magiclogin.entity.MagicLinkSession;
import email.loginwith.secure.keycloak.magiclogin.util.ValidationUtils;
import jakarta.persistence.EntityManager;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;

/**
 * Custom API endpoint used for magic link continuation. The magic link points to this endpoint and the
 * magic key gets validated here.
 *
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MagicLinkContinuationRestResource {

    private final EntityManager em;


    public MagicLinkContinuationRestResource(KeycloakSession session) {
        this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }


    @GET
    @Path("")
    @Produces(MediaType.TEXT_HTML)
    public Response loginWithMagicLink(
            @QueryParam(Constants.QUERY_PARAM_MAGIC_LINK_SESSION_ID) String magicLinkSessionId,
            @QueryParam(Constants.QUERY_PARAM_MAGIC_KEY) String magicKey
    ) {
        if (!ValidationUtils.isUUID(magicLinkSessionId) || !ValidationUtils.isUUID(magicKey)) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        em.getTransaction().begin();
        MagicLinkSession magicLinkSession = em.find(MagicLinkSession.class, magicLinkSessionId);
        boolean loggedIn = false;
        if (magicLinkSession != null) {
            loggedIn = ValidationUtils.isMagicLinkSessionValid(magicLinkSession, magicKey);
            magicLinkSession.setLoggedIn(loggedIn);
        }
        em.getTransaction().commit();

        // Forward the user to the initially opened login page
        if (loggedIn && magicLinkSession.getRedirectUri() != null) {
            return Response.status(Response.Status.FOUND).location(UriBuilder.fromUri(magicLinkSession.getRedirectUri()).build()).build();
        }
        // Login was not successful
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

}
