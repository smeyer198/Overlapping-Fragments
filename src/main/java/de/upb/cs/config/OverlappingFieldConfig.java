package de.upb.cs.config;

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

    @XmlElement(name = "overlappingBytes", defaultValue = "")
    private String overlappingBytes;

    @XmlElement(name = "additionalFragmentIndex", defaultValue = "0")
    private int additionalFragmentIndex;

    /**
     * ClientHello and ServerHello
     *
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, String overlappingBytes) {
        this(field, type, order, splitIndex, overlappingBytes, 0);
    }*/

    /**
     * ClientKeyExchange
     *
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex) {
        this(field, type, order, splitIndex, "");
    }*/

    /**
     * ServerKeyExchange
     *
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order) {
        this(field, type, order, 0, "", 0);
    }*/

    /*
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, int additionalFragmentIndex) {
        this(field, type, order, splitIndex, "", additionalFragmentIndex);
    }*/
    /*
    public OverlappingFieldConfig(OverlappingField field, OverlappingType type, OverlappingOrder order, int splitIndex, String overlappingBytes, int additionalFragmentIndex) {
        this.overlappingField = field;
        this.overlappingType = type;
        this.overlappingOrder = order;
        this.splitIndex = splitIndex;
        this.overlappingBytes = overlappingBytes;
        this.additionalFragmentIndex = additionalFragmentIndex;
    }*/

    public OverlappingFieldConfig() {
        this.overlappingField = OverlappingField.NO_FIELD;
        this.overlappingType = OverlappingType.NO_OVERLAPPING_TYPE;
        this.overlappingOrder = OverlappingOrder.ORIGINAL;
        this.splitIndex = 0;
        this.overlappingBytes = "";
        this.additionalFragmentIndex = 0;
    }

    public void setOverlappingField(OverlappingField field) {
        this.overlappingField = field;
    }

    public OverlappingField getOverlappingField() {
        return overlappingField;
    }

    public void setOverlappingType(OverlappingType type) {
        this.overlappingType = type;
    }

    public OverlappingType getOverlappingType() {
        return overlappingType;
    }

    public void setOverlappingOrder(OverlappingOrder order) {
        this.overlappingOrder = order;
    }

    public OverlappingOrder getOverlappingOrder() {
        return overlappingOrder;
    }

    public void setSplitIndex(int splitIndex) {
        this.splitIndex = splitIndex;
    }

    public int getSplitIndex() {
        return splitIndex;
    }

    public void setOverlappingBytes(String overlappingBytes) {
        this.overlappingBytes = overlappingBytes;
    }

    public String getOverlappingBytes() {
        return overlappingBytes;
    }

    public void setAdditionalFragmentIndex(int additionalFragmentIndex) {
        this.additionalFragmentIndex = additionalFragmentIndex;
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
                "\n\tBytes: " + overlappingBytes +
                "\n\tAdditional index: " + additionalFragmentIndex +
                "\n]";
    }
}
