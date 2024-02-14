package de.upb.cs.util;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

public class LogUtils {

    private static final Logger LOGGER = LogManager.getLogger();

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
        builder.append("\n\tOverlapping bytes: ")
                .append(byteToHexString(overlappingBytes));

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
}
