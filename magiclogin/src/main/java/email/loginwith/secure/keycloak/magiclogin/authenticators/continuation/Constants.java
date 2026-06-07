package email.loginwith.secure.keycloak.magiclogin.authenticators.continuation;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class Constants {

    public static final String QUERY_PARAM_MAGIC_KEY = "magicKey";
    public static final String QUERY_PARAM_MAGIC_LOGIN_SESSION_ID = "id";
    public static final String MAGIC_LOGIN_PROVIDER_FACTORY_ID = "magiclogin-login";


    private Constants() {
        //prevent instantiation
    }
}
