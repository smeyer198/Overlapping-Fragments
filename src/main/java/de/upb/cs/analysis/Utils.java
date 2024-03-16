package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.config.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class Utils {

    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    public static void logOverlappingFragments(Message message, DtlsHandshakeMessageFragment originalFragment, List<DtlsHandshakeMessageFragment> fragments) {
        StringBuilder builder = new StringBuilder();
        builder.append("\nMessage: ").append(message);
        builder.append("\n\tOriginal message:  ")
                .append(byteToHexString(originalFragment.getFragmentContentConfig()));

        for (int i = 0; i < fragments.size(); i++) {
            builder.append("\n\tFragment ")
                    .append(i + 1)
                    .append(":        ")
                    .append("   ".repeat(fragments.get(i).getOffsetConfig()))
                    .append(byteToHexString(fragments.get(i).getFragmentContentConfig()));
        }

        int length = 3 * originalFragment.getFragmentContentConfig().length + 30;
        builder.insert(0, "\n" + "-".repeat(length));
        builder.append("\n")
                .append("-".repeat(length));

        LOGGER.info(builder.toString());
    }

    public static String byteToHexString(byte[] content) {
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
}
