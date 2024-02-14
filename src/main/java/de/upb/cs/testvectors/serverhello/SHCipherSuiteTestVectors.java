package de.upb.cs.testvectors.serverhello;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

public class SHCipherSuiteTestVectors {

    // TLS_RSA_WITH_AES_128_CBC_SHA1
    private static final byte[] cipherSuite = new byte[]{(byte) 0x00, (byte) 0x2f};
    private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA;

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.ORIGINAL,
                2
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.REVERSED,
                2
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
        analysisConfig.setSelectedCipherSuite(selectedCipherSuite);
        return analysisConfig;
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
