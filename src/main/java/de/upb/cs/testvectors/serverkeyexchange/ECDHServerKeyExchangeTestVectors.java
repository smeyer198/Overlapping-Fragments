package de.upb.cs.testvectors.serverkeyexchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.math.BigInteger;

public class ECDHServerKeyExchangeTestVectors {

    private static final CipherSuite serverHelloCipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    private static final SignatureAndHashAlgorithm serverHelloSignatureAndHashAlgorithm = SignatureAndHashAlgorithm.ECDSA_SHA256;

    private static final String privateKey = "5";

    public static OverlappingAnalysisConfig noOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.ORIGINAL,
                20
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                0,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                0,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        analysisConfig.setEcPrivateKey(privateKey);
        return analysisConfig;
    }
}
