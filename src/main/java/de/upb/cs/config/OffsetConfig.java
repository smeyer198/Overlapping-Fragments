package de.upb.cs.config;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "OffsetConfig")
@XmlAccessorType(XmlAccessType.FIELD)
public class OffsetConfig {

    @XmlElement(name = "offset")
    private int offset = Constants.DEFAULT_OFFSET;

    @XmlElement(name = "field")
    private Field field = Field.NONE;

    private OffsetConfig() {}

    public OffsetConfig(int offset) {
        this(offset, Field.NONE);
    }

    public OffsetConfig(int offset, Field field) {
        this.offset = offset;
        this.field = field;
    }

    public int getOffset() {
        return offset;
    }

    public Field getField() {
        return field;
    }
}
