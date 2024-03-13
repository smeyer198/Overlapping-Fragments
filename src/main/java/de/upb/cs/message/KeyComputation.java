package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;

import java.math.BigInteger;

public class KeyComputation {



    public static BigInteger computeDhPublicKey(BigInteger privateKey, TlsContext context) {
        // Follow the same computation as in https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/DHClientKeyExchangePreparator.java
        BigInteger generator = context.getChooser().getServerDhGenerator();
        BigInteger modulus = context.getChooser().getServerDhModulus();

        return generator.modPow(privateKey.abs(), modulus.abs());
    }

    public static Point computeEcPublicKey(BigInteger privateKey, NamedGroup group) {
        // Follow the generation as in https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/ECDHClientKeyExchangePreparator.java
        EllipticCurve curve = CurveFactory.getCurve(group);
        Point publicKeyPoint = curve.mult(privateKey, curve.getBasePoint());

        return curve.getPoint(publicKeyPoint.getFieldX().getData(), publicKeyPoint.getFieldY().getData());
    }
}
