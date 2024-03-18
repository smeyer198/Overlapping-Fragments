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

    public LengthConfig() {}

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public Field getField() {
        return field;
    }

    public void setField(Field field) {
        this.field = field;
    }
}
