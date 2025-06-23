import java.io.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.*;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
//import org.bouncycastle.openssl.PEMEncryptedSubjectPrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import java.security.cert.X509Certificate;



public class ParallelCertScanner {

    private static final String OUTPUT_CSV = "cert_report.csv";
    private static final String PASSWORD = "password"; // Replace with your actual password
    private static final Logger logger = Logger.getLogger(ParallelCertScanner.class.getName());

    static {
        try {
            LogManager.getLogManager().reset();
            FileHandler fh = new FileHandler("cert_parser.log", true);
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            System.err.println("Failed to set up logger: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        String folderPath = "certs"; // Change to your folder path
        List<String[]> rows = Collections.synchronizedList(new ArrayList<>());
        rows.add(new String[]{"Filename", "Serial Number", "Valid From", "Valid To", "Subject", "Issuer"});

        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        AtomicInteger counter = new AtomicInteger();

        Files.walk(Paths.get(folderPath))
            .filter(Files::isRegularFile)
            .forEach(path -> executor.submit(() -> {
                String file = path.toString();
                try {
                    if (file.endsWith(".jks")) {
                        parseKeystore(file, "JKS", PASSWORD, rows);
                    } else if (file.endsWith(".p12") || file.endsWith(".pfx")) {
                        parseKeystore(file, "PKCS12", PASSWORD, rows);
                    } else if (file.endsWith(".pem") || file.endsWith(".crt")) {
                        parsePEM(file, rows);
                    }
                    logger.info("Parsed file: " + file);
                    counter.incrementAndGet();
                } catch (Exception e) {
                    logger.warning("Error parsing " + file + ": " + e.getMessage());
                }
            }));

        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.MINUTES);

        try (PrintWriter writer = new PrintWriter(new FileWriter(OUTPUT_CSV))) {
            for (String[] row : rows) {
                writer.println(String.join(",", escape(row)));
            }
        }

        logger.info("Parsed " + counter.get() + " files. CSV report generated: " + OUTPUT_CSV);
    }

    private static void parseKeystore(String path, String type, String password, List<String[]> rows) throws Exception {
        KeyStore ks = KeyStore.getInstance(type);
        ks.load(new FileInputStream(path), password.toCharArray());
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                addCertRow(path, (X509Certificate) cert, rows);
            }
        }
    }

    private static void parsePEM(String path, List<String[]> rows) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(path))) {
            Object obj;
            while ((obj = pemParser.readObject()) != null) {
                if (obj instanceof X509CertificateHolder) {
                    X509CertificateHolder holder = (X509CertificateHolder) obj;
                    //X509Certificate cert = new JcaPEMKeyConverter().getCertificate(holder);
                    X509Certificate cert = new JcaX509CertificateConverter()
                           .setProvider("BC")
                           .getCertificate(holder);

                    addCertRow(path, cert, rows);
                } else if (obj instanceof PEMEncryptedKeyPair ) { //PEMEncryptedSubjectPrivateKeyInfo) {
                    logger.info("Encrypted private key found in: " + path + " (not extracting)");
                } else {
                    logger.warning("Unrecognized PEM object in: " + path);
                }
            }
        }
    }

    private static void addCertRow(String filename, X509Certificate cert, List<String[]> rows) {
        rows.add(new String[]{
            filename,
            cert.getSerialNumber().toString(),
            cert.getNotBefore().toString(),
            cert.getNotAfter().toString(),
            cert.getSubjectDN().toString(),
            cert.getIssuerDN().toString()
        });
    }

    private static String[] escape(String[] fields) {
        return Arrays.stream(fields)
            .map(f -> "\"" + f.replace("\"", "\"\"") + "\"")
            .toArray(String[]::new);
    }
}

/*
//Maven Dependency for Bouncy Castl
<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcpkix-jdk15on</artifactId>
  <version>1.70</version>
</dependency>
*/