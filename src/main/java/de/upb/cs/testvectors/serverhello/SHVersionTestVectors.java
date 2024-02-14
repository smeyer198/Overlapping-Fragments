package de.upb.cs.testvectors.serverhello;

import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

public class SHVersionTestVectors {

    // DTLS 1.0
    private static final byte[] dtlsVersion = new byte[]{(byte) 0xfe, (byte) 0xff};

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_EMPTY,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.ORIGINAL,
                2
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_EMPTY,
                OverlappingType.NO_OVERLAPPING_TYPE,
                OverlappingOrder.REVERSED,
                2
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                1,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                1,
                new byte[]{dtlsVersion[1]}
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.ORIGINAL,
                2,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_A,
                OverlappingOrder.REVERSED,
                2,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.CONSECUTIVE_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                0,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                0,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                0,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.SERVER_HELLO_VERSION,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                0,
                dtlsVersion
        );
        return new OverlappingAnalysisConfig(connectionConfig, fieldConfig);
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
