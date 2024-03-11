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
    //private static final byte[] cipherSuite = new byte[]{(byte) 0xc0, (byte) 0x2b};
    private static final String cipherSuite = "c0 2b";

    private static final String overlappingByte = "2b";

    // private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    // private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    // private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA;
    private static final CipherSuite selectedCipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;

    private static final SignatureAndHashAlgorithm serverHelloSignatureAndHashAlgorithm = SignatureAndHashAlgorithm.ECDSA_SHA256;

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_BYTES);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(10);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_BYTES);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(10);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(selectedCipherSuite);
        analysisConfig.setServerHelloSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
        return analysisConfig;
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
