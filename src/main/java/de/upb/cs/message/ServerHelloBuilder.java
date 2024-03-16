package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.OffsetConfig;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.OverrideConfig;
import de.upb.cs.analysis.Utils;

import java.util.ArrayList;
import java.util.List;

public class ServerHelloBuilder extends MessageBuilder {

    public ServerHelloBuilder(AnalysisConfig analysisConfig, TlsContext context) {
        super(analysisConfig, context);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> buildFragmentsForMessage(final DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            int messageLength = originalFragment.getFragmentContentConfig().length;
            int offset = parseOffset(fragmentConfig.getOffset(), messageLength);
            int length = parseLength(fragmentConfig.getLength(), offset, messageLength);

            if (fragmentConfig.getOffsetConfig() != null) {
                offset = parseOffset(fragmentConfig.getOffsetConfig(), messageLength);
            }

            if (fragmentConfig.getLengthConfig() != null) {
                length = parseLength(fragmentConfig.getLengthConfig(), offset, messageLength);
            }

            DtlsHandshakeMessageFragment fragment;
            if (fragmentConfig.getOverrideConfig() != null) {
                int index = parseOverrideIndex(fragmentConfig.getOverrideConfig());
                byte[] byteValue = Utils.hexToByteArray(fragmentConfig.getOverrideConfig().getBytes());

                DtlsHandshakeMessageFragment manipulatedFragment = fragmentBuilder.overwriteBytes(originalFragment, index, byteValue);
                fragment = fragmentBuilder.buildFragment(manipulatedFragment, offset, length, fragmentConfig.getPrependBytes(), fragmentConfig.getAppendBytes());
            } else {
                fragment = fragmentBuilder.buildFragment(originalFragment, offset, length, fragmentConfig.getPrependBytes(), fragmentConfig.getAppendBytes());
            }
            fragments.add(fragment);
        }

        return fragments;
    }

    public int parseOffset(OffsetConfig offsetConfig, int messageLength) throws OverlappingFragmentException {
        Field field = offsetConfig.getField();

        switch (field) {
            case NONE:
                if (offsetConfig.getOffset() < 0) {
                    return messageLength + offsetConfig.getOffset();
                }
                return offsetConfig.getOffset();
            case VERSION:
                if (offsetConfig.getOffset() < 0) {
                    return getVersionLastIndex() + offsetConfig.getOffset();
                }
                return getVersionFirstIndex() + offsetConfig.getOffset();
            case CIPHER_SUITE:
                if (offsetConfig.getOffset() < 0) {
                    return getCipherSuiteLastIndex() + offsetConfig.getOffset();
                }
                return getCipherSuiteFirstIndex() + offsetConfig.getOffset();
            default:
                throw new OverlappingFragmentException("Field " + field + " from offset is not allowed in ServerHello");
        }
    }

    public int parseLength(LengthConfig lengthConfig, int offset, int messageLength) throws OverlappingFragmentException {
        if (lengthConfig.getLength() == Integer.MIN_VALUE) {
            return lengthConfig.getLength();
        }

        Field field = lengthConfig.getField();
        switch (field) {
            case NONE:
                if (lengthConfig.getLength() < 0) {
                    return messageLength - offset + lengthConfig.getLength();
                }
                return lengthConfig.getLength();
            case VERSION:
                return getVersionFirstIndex() + lengthConfig.getLength();
            case CIPHER_SUITE:
                return getCipherSuiteFirstIndex() + lengthConfig.getLength();
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ServerHello");
        }
    }

    public int parseOverrideIndex(OverrideConfig overrideConfig) throws OverlappingFragmentException {
        Field field = overrideConfig.getField();

        switch (field) {
            case NONE:
                return overrideConfig.getIndex();
            case VERSION:
                return getVersionFirstIndex() + overrideConfig.getIndex();
            case CIPHER_SUITE:
                return getCipherSuiteFirstIndex() + overrideConfig.getIndex();
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ServerHello");
        }
    }

    public int getVersionFirstIndex() {
        return 0;
    }

    public int getVersionLastIndex() {
        return 2;
    }

    public int getCipherSuiteFirstIndex() {
        // Version(2) + Random + SessionIdLength(1) + SessionId
        return 2 + context.getServerRandom().length + 1 + context.getServerSessionId().length;
    }

    public int getCipherSuiteLastIndex() {
        // Version(2) + Random + SessionIdLength(1) + SessionId + CipherSuite(2)
        return 2 + context.getServerRandom().length + 1 + context.getServerSessionId().length + 2;
    }
}
