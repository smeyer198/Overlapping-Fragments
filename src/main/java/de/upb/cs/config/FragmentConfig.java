package de.upb.cs.config;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "FragmentConfig")
@XmlAccessorType(XmlAccessType.FIELD)
public class FragmentConfig {

    @XmlElement(name = "offset")
    private int offset = Constants.DEFAULT_OFFSET;

    @XmlElement(name = "offsetConfig")
    private OffsetConfig offsetConfig = null;

    @XmlElement(name = "length")
    private int length = Constants.DEFAULT_LENGTH;

    @XmlElement(name = "lengthConfig")
    private LengthConfig lengthConfig = null;

    @XmlElement(name = "overrideConfig")
    private OverrideConfig overrideConfig = null;

    @XmlElement(name = "prependBytes")
    private String prependBytes = "";

    @XmlElement(name = "appendBytes")
    private String appendBytes = "";

    public FragmentConfig() {}

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public OffsetConfig getOffsetConfig() {
        return offsetConfig;
    }

    public void setOffsetConfig(OffsetConfig offsetConfig) {
        this.offsetConfig = offsetConfig;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public LengthConfig getLengthConfig() {
        return lengthConfig;
    }

    public void setLengthConfig(LengthConfig lengthConfig) {
        this.lengthConfig = lengthConfig;
    }

    public OverrideConfig getOverrideConfig() {
        return overrideConfig;
    }

    public void setOverrideConfig(OverrideConfig overrideConfig) {
        this.overrideConfig = overrideConfig;
    }

    public String getPrependBytes() {
        return prependBytes;
    }

    public void setPrependBytes(String prependBytes) {
        this.prependBytes = prependBytes;
    }

    public String getAppendBytes() {
        return appendBytes;
    }

    public void setAppendBytes(String appendBytes) {
        this.appendBytes = appendBytes;
    }
}
