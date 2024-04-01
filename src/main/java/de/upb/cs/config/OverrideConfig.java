package de.upb.cs.config;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "OverrideConfig")
@XmlAccessorType(XmlAccessType.FIELD)
public class OverrideConfig {

    @XmlElement(name = "index")
    private int index = 0;

    @XmlElement(name = "bytes")
    private String bytes = "";

    @XmlElement(name = "field")
    private Field field = Field.NONE;

    private OverrideConfig() {}

    public OverrideConfig(int index, String bytes) {
        this(index, bytes, Field.NONE);
    }

    public OverrideConfig(int index, String bytes, Field field) {
        this.index = index;
        this.bytes = bytes;
        this.field = field;
    }

    public int getIndex() {
        return index;
    }

    public String getBytes() {
        return bytes;
    }

    public Field getField() {
        return field;
    }
}
