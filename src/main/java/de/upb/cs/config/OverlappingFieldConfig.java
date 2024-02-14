package de.upb.cs.config;

public class OverlappingFieldConfig {

    private final OverlappingField overlappingField;
    private final OverlappingType overlappingType;
    private final OverlappingOrder overlappingOrder;
    private final int splitIndex;
    private byte[] overlappingBytes;
    private final int additionalFragmentIndex;

    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex) {
        this(field, type, order, splitIndex, new byte[]{});
    }

    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, byte[] overlappingBytes) {
        this(field, type, order, splitIndex, overlappingBytes, 0);
    }

    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, byte[] overlappingBytes, int additionalFragmentIndex) {
        this.overlappingField = field;
        this.overlappingType = type;
        this.overlappingOrder = order;
        this.splitIndex = splitIndex;
        this.overlappingBytes = overlappingBytes;
        this.additionalFragmentIndex = additionalFragmentIndex;
    }

    public OverlappingField getOverlappingField() {
        return overlappingField;
    }

    public OverlappingType getOverlappingType() {
        return overlappingType;
    }

    public OverlappingOrder getOverlappingOrder() {
        return overlappingOrder;
    }

    public int getSplitIndex() {
        return splitIndex;
    }

    public byte[] getOverlappingBytes() {
        return overlappingBytes;
    }

    public void setOverlappingBytes(byte[] overlappingBytes) {
        this.overlappingBytes = overlappingBytes;
    }

    public int getAdditionalFragmentIndex() {
        return additionalFragmentIndex;
    }
}
