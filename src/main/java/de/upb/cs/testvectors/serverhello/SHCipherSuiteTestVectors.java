package de.upb.cs.testvectors.serverhello;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

public class SHCipherSuiteTestVectors {

    // TLS_RSA_WITH_AES_128_CBC_SHA1
    // private static final byte[] cipherSuite = new byte[]{(byte) 0x00, (byte) 0x2f};

    // TLS_ECDHE_RSA_WITH_AES_128_CGM_SHA256
    // private static final byte[] cipherSuite = new byte[]{(byte) 0xc0, (byte) 0x2f};

    // Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
    private static final byte[] cipherSuite = new byte[]{(byte) 0xc0, (byte) 0x2b};

    // private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    // private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    // private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA;
    private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;

    private static final SignatureAndHashAlgorithm serverHelloSignatureAndHashAlgorithm = SignatureAndHashAlgorithm.ECDSA_SHA256;

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.ORIGINAL,
                2
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.REVERSED,
                2
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{cipherSuite[1]}
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{cipherSuite[1]},
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{cipherSuite[1]},
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{cipherSuite[1]},
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{cipherSuite[1]},
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                cipherSuite
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                0,
                cipherSuite,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                0,
                cipherSuite,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                cipherSuite,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_CIPHER_SUITE,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                cipherSuite,
                -1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
