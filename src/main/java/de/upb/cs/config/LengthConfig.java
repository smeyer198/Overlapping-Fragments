package de.upb.cs.config;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "LengthConfig")
@XmlAccessorType(XmlAccessType.FIELD)
public class LengthConfig {

    @XmlElement(name = "length")
    private int length = Constants.DEFAULT_LENGTH;

    @XmlElement(name = "field")
    private Field field = Field.NONE;

    private LengthConfig() {}

    public LengthConfig(int length) {
        this(length, Field.NONE);
    }

    public LengthConfig(int length, Field field) {
        this.length = length;
        this.field = field;
    }

    public int getLength() {
        return length;
    }

    public Field getField() {
        return field;
    }
}
