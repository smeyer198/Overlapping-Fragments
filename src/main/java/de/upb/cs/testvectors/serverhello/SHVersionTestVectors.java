package de.upb.cs.testvectors.serverhello;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

public class SHVersionTestVectors {

    // DTLS 1.0
    private static final byte[] dtlsVersion = new byte[]{(byte) 0xfe, (byte) 0xff};

    private static final CipherSuite serverHelloCipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    private static final SignatureAndHashAlgorithm serverHelloSignatureAndHashAlgorithm = SignatureAndHashAlgorithm.ECDSA_SHA256;

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.ORIGINAL,
                2
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.REVERSED,
                2
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                new byte[]{dtlsVersion[1]}
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                new byte[]{dtlsVersion[1]}
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{dtlsVersion[1]}
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{dtlsVersion[1]}
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{dtlsVersion[1]},
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{dtlsVersion[1]},
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{dtlsVersion[1]},
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{dtlsVersion[1]},
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                0,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                0,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                dtlsVersion,
                -1
        );
        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
