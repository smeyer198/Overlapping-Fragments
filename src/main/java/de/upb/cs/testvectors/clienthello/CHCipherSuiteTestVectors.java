package de.upb.cs.testvectors.clienthello;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.Arrays;
import java.util.List;

public class CHCipherSuiteTestVectors {

    // TLS_RSA_WITH_AES_128_CBC_SHA1
    private static final String cipherSuite = "c0 2c c0 2b";// new byte[]{(byte) 0xc0, (byte) 0x2c, (byte) 0xc0, (byte) 0x2b};
    private static final String cipherSuiteByte = "2c";
    private static final List<CipherSuite> supportedCipherSuites = Arrays.asList(
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            //CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
            //CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
            //CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    );

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_TYPE);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(2);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_TYPE);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(2);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(cipherSuiteByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(4);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(4);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_CIPHER_SUITE);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(cipherSuite);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(supportedCipherSuites);
        return analysisConfig;
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
