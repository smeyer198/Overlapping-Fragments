package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class OverlappingFragmentBuilder {

    public static List<DtlsHandshakeMessageFragment> buildOverlappingFragments(DtlsHandshakeMessageFragment originalFragment, OverlappingType type, OverlappingOrder order, int splitIndex, byte[] overlappingBytes, int additionalFragmentIndex) throws OverlappingFragmentException {
        switch (type) {
            case NO_OVERLAPPING_TYPE:
                return buildFragmentsWithoutOverlappingBytes(originalFragment, splitIndex, order);
            case CONSECUTIVE_TYPE_A:
                return buildConsecutiveTypeAFragments(originalFragment, splitIndex, overlappingBytes, order, additionalFragmentIndex);
            case CONSECUTIVE_TYPE_B:
                return buildConsecutiveTypeBFragments(originalFragment, splitIndex, overlappingBytes, order, additionalFragmentIndex);
            case SUBSEQUENT_TYPE_A:
                return buildSubsequentTypeAFragments(originalFragment, splitIndex, overlappingBytes, order, additionalFragmentIndex);
            case SUBSEQUENT_TYPE_B:
                return buildSubsequentTypeBFragments(originalFragment, splitIndex, overlappingBytes, order, additionalFragmentIndex);
            default:
                throw new OverlappingFragmentException("Fragment type " + type + " is not supported");
        }
    }

    private static List<DtlsHandshakeMessageFragment> buildFragmentsWithoutOverlappingBytes(DtlsHandshakeMessageFragment originalFragment, int splitIndex, OverlappingOrder order) throws OverlappingFragmentException {
        // Split the original message at splitIndex
        byte[] originalData = originalFragment.getFragmentContentConfig();
        byte[] firstFragmentData = Arrays.copyOfRange(originalData, 0, splitIndex);
        byte[] secondFragmentData = Arrays.copyOfRange(originalData, splitIndex, originalData.length);

        DtlsHandshakeMessageFragment firstFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                firstFragmentData,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig(),
                originalFragment.getHandshakeMessageLengthConfig()
        );

        DtlsHandshakeMessageFragment secondFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                secondFragmentData,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig() + firstFragmentData.length,
                originalFragment.getHandshakeMessageLengthConfig()
        );

        return orderFragments(firstFragment, secondFragment, order);
    }

    private static List<DtlsHandshakeMessageFragment> buildConsecutiveTypeAFragments(
            DtlsHandshakeMessageFragment originalFragment,
            int splitIndex,
            byte[] overlappingBytes,
            OverlappingOrder order,
            int additionalFragmentIndex
    ) throws OverlappingFragmentException {

        byte[] originalData = originalFragment.getFragmentContentConfig();
        byte[] firstFragmentData = Arrays.copyOfRange(originalData, 0, splitIndex);
        byte[] secondFragmentData = Arrays.copyOfRange(originalData, splitIndex, originalData.length);
        // Prepend the extra bytes to the second fragment
        byte[] modifiedSecondFragmentData = ArrayConverter.concatenate(overlappingBytes, secondFragmentData);

        // Create the overlappingFragments
        DtlsHandshakeMessageFragment firstFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                firstFragmentData,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig(),
                originalFragment.getHandshakeMessageLengthConfig()
        );

        DtlsHandshakeMessageFragment secondFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                // Insert manipulated bytes
                modifiedSecondFragmentData,
                originalFragment.getMessageSequenceConfig(),
                // Adapt offset
                originalFragment.getOffsetConfig() + firstFragmentData.length - overlappingBytes.length,
                originalFragment.getHandshakeMessageLengthConfig()
        );

        if (additionalFragmentIndex == 0) {
            return orderFragments(firstFragment, secondFragment, order);
        }

        List<DtlsHandshakeMessageFragment> additionalFragments;

        if (additionalFragmentIndex < 0) {
            if (order == OverlappingOrder.ORIGINAL) {
                additionalFragments = buildAdditionalFragment(secondFragment, additionalFragmentIndex);

                return orderFragments(firstFragment, additionalFragments.get(0), order, additionalFragments.get(1));
            } else {
                additionalFragments = buildAdditionalFragment(secondFragment, additionalFragmentIndex);

                return orderFragments(firstFragment, additionalFragments.get(0), order, additionalFragments.get(1));
            }
        } else {
            if (order == OverlappingOrder.ORIGINAL) {
                additionalFragments = buildAdditionalFragment(firstFragment, additionalFragmentIndex);

                return orderFragments(additionalFragments.get(1), secondFragment, order, additionalFragments.get(0));
            } else {
                additionalFragments = buildAdditionalFragment(firstFragment, additionalFragmentIndex);

                return orderFragments(secondFragment, additionalFragments.get(1), order, additionalFragments.get(0));
            }
        }
    }

    private static List<DtlsHandshakeMessageFragment> buildConsecutiveTypeBFragments(
            DtlsHandshakeMessageFragment originalFragment,
            int splitIndex,
            byte[] overlappingBytes,
            OverlappingOrder order,
            int additionalFragmentIndex
    ) throws OverlappingFragmentException {
        byte[] originalData = originalFragment.getFragmentContentConfig();
        byte[] firstFragmentData = Arrays.copyOfRange(originalData, 0, splitIndex);
        byte[] secondFragmentData = Arrays.copyOfRange(originalData, splitIndex, originalData.length);
        // Append the overlapping byte to the first fragments
        byte[] modifiedFirstFragmentData = ArrayConverter.concatenate(firstFragmentData, overlappingBytes);

        DtlsHandshakeMessageFragment firstFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                modifiedFirstFragmentData,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig(),
                originalFragment.getHandshakeMessageLengthConfig()
        );

        DtlsHandshakeMessageFragment secondFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                secondFragmentData,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig() + firstFragmentData.length,
                originalFragment.getHandshakeMessageLengthConfig()
        );

        if (additionalFragmentIndex == 0) {
            return orderFragments(firstFragment, secondFragment, order);
        }

        List<DtlsHandshakeMessageFragment> additionalFragments = buildAdditionalFragment(secondFragment, additionalFragmentIndex);
        return orderFragments(additionalFragments.get(0), firstFragment, order, additionalFragments.get(1));
    }

    private static List<DtlsHandshakeMessageFragment> buildSubsequentTypeAFragments(
            DtlsHandshakeMessageFragment originalFragment,
            int splitIndex,
            byte[] overlappingBytes,
            OverlappingOrder order,
            int additionalFragmentIndex
    ) throws OverlappingFragmentException {
        DtlsHandshakeMessageFragment firstFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                originalFragment.getFragmentContentConfig(),
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig(),
                originalFragment.getHandshakeMessageLengthConfig()
        );

        DtlsHandshakeMessageFragment secondFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                overlappingBytes,
                originalFragment.getMessageSequenceConfig(),
                // Adapt the offset
                originalFragment.getOffsetConfig() + splitIndex,
                originalFragment.getHandshakeMessageLengthConfig()
        );

        if (additionalFragmentIndex == 0) {
            return orderFragments(firstFragment, secondFragment, order);
        }

        List<DtlsHandshakeMessageFragment> additionalFragments = buildAdditionalFragment(firstFragment, additionalFragmentIndex);
        return orderFragments(additionalFragments.get(0), secondFragment, order, additionalFragments.get(1));
    }

    private static List<DtlsHandshakeMessageFragment> buildSubsequentTypeBFragments(
            DtlsHandshakeMessageFragment originalFragment,
            int splitIndex,
            byte[] overlappingBytes,
            OverlappingOrder order,
            int additionalFragmentIndex
    ) throws OverlappingFragmentException {
        byte[] originalData = originalFragment.getFragmentContentConfig();
        byte[] leftData = Arrays.copyOfRange(originalData, 0, splitIndex);
        byte[] middleData = Arrays.copyOfRange(originalData, splitIndex, splitIndex + overlappingBytes.length);
        byte[] rightData = Arrays.copyOfRange(originalData, splitIndex + overlappingBytes.length, originalData.length);
        byte[] modifiedCoveringData = ArrayConverter.concatenate(leftData, overlappingBytes, rightData);

        DtlsHandshakeMessageFragment firstFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                // Insert manipulated bytes
                modifiedCoveringData,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig(),
                originalFragment.getHandshakeMessageLengthConfig()
        );

        DtlsHandshakeMessageFragment secondFragment = new DtlsHandshakeMessageFragment(
                originalFragment.getHandshakeMessageTypeConfig(),
                // Insert original bytes into the subsequent fragment
                middleData,
                originalFragment.getMessageSequenceConfig(),
                originalFragment.getOffsetConfig() + splitIndex,
                originalFragment.getHandshakeMessageLengthConfig()
        );

        if (additionalFragmentIndex == 0) {
            return orderFragments(firstFragment, secondFragment, order);
        }

        List<DtlsHandshakeMessageFragment> additionalFragments = buildAdditionalFragment(firstFragment, additionalFragmentIndex);
        return orderFragments(additionalFragments.get(0), secondFragment, order, additionalFragments.get(1));
    }

    private static List<DtlsHandshakeMessageFragment> buildAdditionalFragment(DtlsHandshakeMessageFragment fragment, int index) throws OverlappingFragmentException {
        byte[] originalData = fragment.getFragmentContentConfig();

        // TODO make this more dynamic/flexible
        if (index < 0) {
            return buildFragmentsWithoutOverlappingBytes(fragment, originalData.length + index, OverlappingOrder.ORIGINAL);
        } else {
            return buildFragmentsWithoutOverlappingBytes(fragment, index, OverlappingOrder.REVERSED);
        }

    }

    private static List<DtlsHandshakeMessageFragment> orderFragments(DtlsHandshakeMessageFragment firstFragment, DtlsHandshakeMessageFragment secondFragment, OverlappingOrder order, DtlsHandshakeMessageFragment... additionalFragments) throws OverlappingFragmentException {
        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        switch (order) {
            case ORIGINAL:
                fragments.add(firstFragment);
                fragments.add(secondFragment);
                break;
            case REVERSED:
                fragments.add(secondFragment);
                fragments.add(firstFragment);
                break;
            default:
                throw new OverlappingFragmentException("Cannot send fragments in order " + order);
        }

        fragments.addAll(Arrays.asList(additionalFragments));
        return fragments;
    }
}
