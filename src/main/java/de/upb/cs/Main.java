package de.upb.cs;

import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.testvectors.clienthello.CHCipherSuiteTestVectors;

public class Main {

    // IP and Port for connecting to a server (found by ifconfig) -> 172.19.142.193
    private static final String CLIENT_IP = "172.19.142.193";
    //private static final String CLIENT_IP = "127.0.0.1";
    private static final int CLIENT_PORT = 8090;
    //private static final int CLIENT_PORT = 4444;

    // IP and Port for accepting connections from a client (found by ping "$(hostname).local")
    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 8080;

    public static void main(String[] args) throws OverlappingFragmentException {
        ConnectionConfig connectionConfig = Main.createConnectionConfig();

        OverlappingAnalysisConfig analysisConfig;
        analysisConfig = CHCipherSuiteTestVectors.subsequentTypeBReversedOrderSingleOverlappingByte();

        analysisConfig.setFragmentFirstCHMessage(false);
        analysisConfig.setCookieExchange(true);

        analysisConfig.setIndividualTransportPacketsForFragments(true);
        analysisConfig.setOverlappingBytesInDigest(false);
        analysisConfig.setClientAuthentication(false);
        analysisConfig.setAddRenegotiationInfoExtension(false);

        analysisConfig.setUseUpdatedKeys(false);

        //analysisConfig.setUpdateProtocolVersion(ProtocolVersion.DTLS10);
        //analysisConfig.setUpdateCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

        //analysisConfig.setCertificatePath("src/main/resources/certs/ec_client_cert.pem");
        //analysisConfig.setCertificateKeyPath("src/main/resources/certs/ec_client_key.pem");

        analysisConfig.setCertificatePath("src/main/resources/certs/rsa_client_cert.pem");
        analysisConfig.setCertificateKeyPath("src/main/resources/certs/rsa_client_key.pem");

        OverlappingFragmentAnalysis analysis = new OverlappingFragmentAnalysis(connectionConfig, analysisConfig);
        analysis.executeAnalysis();
    }

    private static ConnectionConfig createConnectionConfig() {
        ConnectionConfig connectionConfig = new ConnectionConfig();

        connectionConfig.setClientHostname(CLIENT_IP);
        connectionConfig.setClientPort(CLIENT_PORT);
        connectionConfig.setClientTimeout(2000);   // 2 sec

        connectionConfig.setServerHostname(SERVER_IP);
        connectionConfig.setServerPort(SERVER_PORT);
        connectionConfig.setServerTimeout(15000);   // 15 secs

        return connectionConfig;
    }
}