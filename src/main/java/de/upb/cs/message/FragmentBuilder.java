package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.upb.cs.analysis.Utils;

import java.util.Arrays;

public class FragmentBuilder {

    public DtlsHandshakeMessageFragment buildFragment(
            HandshakeMessageType messageType,
            byte[] messageContent,
            int messageLength,
            int offset,
            int length,
            int messageSequence,
            String prependBytes,
            String appendBytes) {
        byte[] prepend = Utils.hexToByteArray(prependBytes);
        byte[] append = Utils.hexToByteArray(appendBytes);

        return buildFragment(messageType, messageContent, messageLength, offset, length, messageSequence, prepend, append);
    }

    public DtlsHandshakeMessageFragment buildFragment(
            HandshakeMessageType messageType,
            byte[] messageContent,
            int messageLength,
            int offset,
            int length,
            int messageSequence,
            byte[] prependBytes,
            byte[] appendBytes) {
        // If no length is given, the fragment is computed over all remaining bytes
        if (length < 0) {
            length = messageLength - offset;
        }

        byte[] fragmentBytes = Arrays.copyOfRange(messageContent, offset, offset + length);
        byte[] extendedFragmentBytes = ArrayConverter.concatenate(prependBytes, fragmentBytes, appendBytes);

        return new DtlsHandshakeMessageFragment(
                messageType,
                extendedFragmentBytes,
                messageSequence,
                offset - prependBytes.length,
                messageLength
        );
    }

    public byte[] overwriteBytes(byte[] originalBytes, int startIndex, byte[] updatedBytes) {
        byte[] manipulatedBytes = Arrays.copyOfRange(originalBytes, 0, originalBytes.length);

        System.arraycopy(updatedBytes, 0, manipulatedBytes, startIndex, updatedBytes.length);

        return manipulatedBytes;
    }
}
