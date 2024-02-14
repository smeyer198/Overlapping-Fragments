package de.upb.cs.testvectors.clientkeyexchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.Arrays;
import java.util.List;

public class RSAKeyExchangeTestVectors {

    private static final int splitIndex = 2;
    private static final List<CipherSuite> cipherSuites = Arrays.asList(
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256
    );

    public static OverlappingAnalysisConfig noOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_RSA,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.ORIGINAL,
                2
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_RSA,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                splitIndex,
                new byte[]{},
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_RSA,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                splitIndex,
                new byte[]{},
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_RSA,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                splitIndex,
                new byte[]{},
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_RSA,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                splitIndex,
                new byte[]{},
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        return analysisConfig;
    }
}
