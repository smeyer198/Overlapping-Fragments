package de.upb.cs;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.testvectors.clienthello.CHCipherSuiteTestVectors;
import de.upb.cs.testvectors.clienthello.CHExtensionTestVectors;
import de.upb.cs.testvectors.clienthello.CHVersionTestVectors;
import de.upb.cs.testvectors.clientkeyexchange.DHKeyExchangeTestVectors;
import de.upb.cs.testvectors.clientkeyexchange.ECDHKeyExchangeTestVectors;
import de.upb.cs.testvectors.clientkeyexchange.RSAKeyExchangeTestVectors;
import de.upb.cs.testvectors.serverhello.SHCipherSuiteTestVectors;
import de.upb.cs.testvectors.serverhello.SHVersionTestVectors;

public class Main {

    // IP and Port for connecting to a server (found by ifconfig) -> 172.19.142.193
    private static final String CLIENT_IP = "172.19.142.193";
    private static final int CLIENT_PORT = 8090;

    //private static final String CLIENT_IP = "127.0.0.1";
    //private static final int CLIENT_PORT = 4444;

    // IP and Port for accepting connections from a client (found by ping "$(hostname).local")
    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 8080;

    public static void main(String[] args) throws OverlappingFragmentException {
        ConnectionConfig connectionConfig = Main.createConnectionConfig();

        OverlappingAnalysisConfig analysisConfig;

        analysisConfig = DHKeyExchangeTestVectors.subsequentTypeBReversedOrder(connectionConfig);

        analysisConfig.setOverlappingBytesInDigest(false);
        analysisConfig.setFragmentFirstCHMessage(false);
        analysisConfig.setIndividualTransportPacketsForFragments(true);
        analysisConfig.setCookieExchange(true);
        analysisConfig.setClientAuthentication(true);

        OverlappingFragmentAnalysis analysis = new OverlappingFragmentAnalysis(analysisConfig);
        analysis.executeAnalysis();
    }

    private static ConnectionConfig createConnectionConfig() {
        ConnectionConfig connectionConfig = new ConnectionConfig();

        connectionConfig.setClientHostname(CLIENT_IP);
        connectionConfig.setClientPort(CLIENT_PORT);
        connectionConfig.setClientTimeout(1000);   // 1 sec

        connectionConfig.setServerHostname(SERVER_IP);
        connectionConfig.setServerPort(SERVER_PORT);
        connectionConfig.setServerTimeout(30000);   // 30 secs

        return connectionConfig;
    }
}