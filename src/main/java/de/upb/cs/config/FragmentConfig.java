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

    public OffsetConfig getOffsetConfig() {
        return offsetConfig;
    }

    public int getLength() {
        return length;
    }

    public LengthConfig getLengthConfig() {
        return lengthConfig;
    }

    public OverrideConfig getOverrideConfig() {
        return overrideConfig;
    }

    public String getPrependBytes() {
        return prependBytes;
    }

    public String getAppendBytes() {
        return appendBytes;
    }

}
