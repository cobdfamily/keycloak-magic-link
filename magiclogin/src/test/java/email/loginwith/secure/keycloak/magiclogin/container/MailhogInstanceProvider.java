package email.loginwith.secure.keycloak.magiclogin.container;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

/**
 * @author Ludwig Burtscher (ludwig.burtscher@cloudflight.io)
 */
public class MailhogInstanceProvider {

    private static final int MAILHOG_PORT_SMTP = 1025;
    private static final int MAILHOG_PORT_HTTP = 8025;

    private static final GenericContainer<?> mailhog = new GenericContainer<>("mailhog/mailhog")
          .withExposedPorts(MAILHOG_PORT_SMTP, MAILHOG_PORT_HTTP)
          .waitingFor(Wait.forListeningPorts(MAILHOG_PORT_SMTP, MAILHOG_PORT_HTTP));


    public static void start() {
        mailhog.start();
    }

    public static void stop() {
        mailhog.close();
    }


    public static MailhogInstanceInfo getInfo() {
        return new MailhogInstanceInfo(
              mailhog.getMappedPort(MAILHOG_PORT_SMTP),
              "http://%s:%d/api/v1/".formatted(mailhog.getHost(), mailhog.getMappedPort(MAILHOG_PORT_HTTP)),
              "http://%s:%d/api/v2/".formatted(mailhog.getHost(), mailhog.getMappedPort(MAILHOG_PORT_HTTP))
        );
    }


    public record MailhogInstanceInfo(
          int smtpPort,
          String apiV1Url,
          String apiV2Url
    ) {

    }
}
