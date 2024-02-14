package de.upb.cs.testvectors.clienthello;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.Arrays;
import java.util.List;

public class CHExtensionTestVectors {

    //  ECDSA_SHA256(0x0403)
    private static final byte[] signatureAndHashAlgorithm = new byte[]{(byte) 0x04, (byte) 0x03, (byte) 0x04, (byte) 0x03};
    private static final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = Arrays.asList(
            SignatureAndHashAlgorithm.RSA_SHA256,
            SignatureAndHashAlgorithm.ECDSA_SHA256
    );
    private static final List<CipherSuite> cipherSuites = Arrays.asList(
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    );
    private static final List<NamedGroup> supportedGroups = Arrays.asList(
            NamedGroup.SECP256R1
    );

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EMPTY,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.ORIGINAL,
                0
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        analysisConfig.setAddEllipticCurveExtension(false);
        analysisConfig.setSupportedGroups(supportedGroups);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EMPTY,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.REVERSED,
                0
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        analysisConfig.setAddEllipticCurveExtension(false);
        analysisConfig.setSupportedGroups(supportedGroups);
        return analysisConfig;
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                new byte[]{signatureAndHashAlgorithm[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        analysisConfig.setAddEllipticCurveExtension(false);
        analysisConfig.setSupportedGroups(supportedGroups);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                new byte[]{signatureAndHashAlgorithm[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{signatureAndHashAlgorithm[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{signatureAndHashAlgorithm[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{signatureAndHashAlgorithm[1]},
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{signatureAndHashAlgorithm[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{signatureAndHashAlgorithm[1]},
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{signatureAndHashAlgorithm[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                4,
                signatureAndHashAlgorithm
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                4,
                signatureAndHashAlgorithm
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                signatureAndHashAlgorithm
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                signatureAndHashAlgorithm
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                0,
                signatureAndHashAlgorithm,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                0,
                signatureAndHashAlgorithm
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                signatureAndHashAlgorithm,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_HELLO_EXTENSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                signatureAndHashAlgorithm
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
