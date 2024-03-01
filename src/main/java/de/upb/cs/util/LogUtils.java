package de.upb.cs.util;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class LogUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogUtils.class);

    public static void logOverlappingFragments(DtlsHandshakeMessageFragment originalFragment, byte[] overlappingBytes, List<DtlsHandshakeMessageFragment> fragments) {
        StringBuilder builder = new StringBuilder();
        builder.append("\n\tOriginal message:  ")
                .append(byteToHexString(originalFragment.getFragmentContentConfig()));

        for (int i = 0; i < fragments.size(); i++) {
            builder.append("\n\tFragment ")
                    .append(i)
                    .append(":        ")
                    .append("   ".repeat(fragments.get(i).getOffsetConfig()))
                    .append(byteToHexString(fragments.get(i).getFragmentContentConfig()));
        }
        //builder.append("\n\tOverlapping bytes: ")
        //        .append(byteToHexString(overlappingBytes));

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
