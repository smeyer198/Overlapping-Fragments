package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    public static String bytesToHexString(byte[] content) {
        StringBuilder sb = new StringBuilder();

        for (byte b : content) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public static byte[] hexToByteArray(String src) {
        // Copied from https://stackoverflow.com/questions/11208479/how-do-i-initialize-a-byte-array-in-java/53463843#53463843
        byte[] biBytes = new BigInteger("10" + src.replaceAll("\\s", ""), 16).toByteArray();
        return Arrays.copyOfRange(biBytes, 1, biBytes.length);
    }

    public static void logFragments(HandshakeMessage<?> message, List<DtlsHandshakeMessageFragment> fragments) {
        StringBuilder builder = new StringBuilder();
        builder.append("\nMessage: ").append(message.getHandshakeMessageType());
        builder.append("\n\tOriginal message:  ")
                .append(Utils.bytesToHexString(message.getMessageContent().getValue()));

        for (int i = 0; i < fragments.size(); i++) {
            builder.append("\n\tFragment ")
                    .append(i + 1)
                    .append(":        ")
                    .append("   ".repeat(fragments.get(i).getOffsetConfig()))
                    .append(Utils.bytesToHexString(fragments.get(i).getFragmentContentConfig()));
        }

        int length = 3 * message.getMessageContent().getValue().length + 30;
        builder.insert(0, "\n" + "-".repeat(length));
        builder.append("\n")
                .append("-".repeat(length));

        LOGGER.info(builder.toString());
    }
}
