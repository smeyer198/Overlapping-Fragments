package de.upb.cs.testvectors.clientkeyexchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.Arrays;
import java.util.List;

public class DHClientKeyExchangeTestVectors {

    private static final int splitIndex = 2;
    private static final List<CipherSuite> cipherSuites = Arrays.asList(
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    );
    private static final String privateKey = "FEFE";

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_DH,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                splitIndex,
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_DH,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                splitIndex,
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_DH,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                splitIndex,
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_DH,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                splitIndex,
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }
}