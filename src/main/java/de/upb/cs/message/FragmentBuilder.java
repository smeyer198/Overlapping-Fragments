package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.analysis.Utils;

import java.util.Arrays;

public class FragmentBuilder {

    public DtlsHandshakeMessageFragment buildFragment(DtlsHandshakeMessageFragment originalFragment, int offset, int length, String prependBytes, String appendBytes) {
        byte[] prepend = Utils.hexToByteArray(prependBytes);
        byte[] append = Utils.hexToByteArray(appendBytes);

        return buildFragment(originalFragment, offset, length, prepend, append);
    }

    public DtlsHandshakeMessageFragment buildFragment(DtlsHandshakeMessageFragment originalFragment, int offset, int length, byte[] prependBytes, byte[] appendBytes) {
        byte[] originalBytes = originalFragment.getFragmentContentConfig();
        // If no length is given, the fragment is computed for all remaining bytes
        if (length < 0) {
            length = originalBytes.length - offset;
        }

        byte[] fragmentBytes = Arrays.copyOfRange(originalBytes, offset, offset + length);
        byte[] modifiedFragmentBytes = ArrayConverter.concatenate(prependBytes, fragmentBytes, appendBytes);

        return new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                modifiedFragmentBytes,
                originalFragment.getMessageSequenceConfig(),
                offset - prependBytes.length,
                originalFragment.getHandshakeMessageLengthConfig()
        );
    }

    public DtlsHandshakeMessageFragment overwriteBytes(DtlsHandshakeMessageFragment originalFragment, int startIndex, byte[] publicKey) {
        byte[] originalBytes = originalFragment.getFragmentContentConfig();
        byte[] manipulatedBytes = Arrays.copyOfRange(originalBytes, 0, originalBytes.length);

        System.arraycopy(publicKey, 0, manipulatedBytes, startIndex, publicKey.length);

        return new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                manipulatedBytes,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig(),
                originalFragment.getHandshakeMessageLengthConfig()
        );
    }
}
