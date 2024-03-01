package de.upb.cs.config;

import de.upb.cs.util.LogUtils;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "FieldConfig")
@XmlAccessorType(XmlAccessType.FIELD)
public class OverlappingFieldConfig {

    @XmlElement(name = "field", required = true)
    private OverlappingField overlappingField;

    @XmlElement(name = "type", required = true)
    private OverlappingType overlappingType;

    @XmlElement(name = "order", required = true)
    private OverlappingOrder overlappingOrder;

    @XmlElement(name = "splitIndex", defaultValue = "0")
    private int splitIndex;

    @XmlElement(name = "overlappingHexBytes", defaultValue = "")
    private String overlappingHexBytes;

    @XmlElement
    private byte[] overlappingBytes;

    @XmlElement(name = "additionalFragmentIndex", defaultValue = "0")
    private int additionalFragmentIndex;

    /**
     * ClientHello and ServerHello
     */
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, byte[] overlappingBytes) {
        this(field, type, order, splitIndex, overlappingBytes, 0);
    }

    /**
     * ClientKeyExchange
     */
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex) {
        this(field, type, order, splitIndex, new byte[]{});
    }

    /**
     * ServerKeyExchange
     */
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order) {
        this(field, type, order, 0, new byte[]{}, 0);
    }

    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, int additionalFragmentIndex) {
        this(field, type, order, splitIndex, new byte[]{}, additionalFragmentIndex);
    }

    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, byte[] overlappingBytes, int additionalFragmentIndex) {
        this.overlappingField = field;
        this.overlappingType = type;
        this.overlappingOrder = order;
        this.splitIndex = splitIndex;
        this.overlappingBytes = overlappingBytes;
        this.additionalFragmentIndex = additionalFragmentIndex;
    }

    private OverlappingFieldConfig() {
        overlappingBytes = new byte[]{};
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

    public String getOverlappingHexBytes() {
        return overlappingHexBytes;
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

    @Override
    public String toString() {
        return "[\tField: " + overlappingField +
                "\n\tType: " + overlappingType +
                "\n\tOrder: " + overlappingOrder +
                "\n\tSplit Index: " + splitIndex +
                "\n\tBytes: " + LogUtils.byteToHexString(overlappingBytes) +
                "\n\tAdditional index: " + additionalFragmentIndex +
                "\n]";
    }
}
