public class Permutation {

    public static byte[] permute(byte[] value, int[] rule, boolean lowToHigh, int startIndex) {
        int resultLength = (rule.length + 7) / 8;
        byte[] result = new byte[resultLength];

        for (int i = 0; i < rule.length; i++) {
            int sourceIndex = rule[i] - startIndex;
            int bit = getBit(value, sourceIndex, lowToHigh);
            setBit(result, i, bit, lowToHigh);
        }
        return result;
    }

    private static int getBit(byte[] data, int index, boolean lowToHigh) {
        if (index < 0 || index >= data.length * 8) {
            throw new IllegalArgumentException("Bit index is out of range: " + index);
        }
        int byteNumber = index / 8;
        int bitInByte = index % 8;
        int shift;
        if (lowToHigh) {
            shift = bitInByte;
        } else {
            shift = 7 - bitInByte;
        }
        return (data[byteNumber] >> shift) & 1;
    }

    private static void setBit(byte[] data, int index, int bit, boolean lowToHigh) {
        int byteNumber = index / 8;
        int bitInByte = index % 8;
        int shift;
        if (lowToHigh) {
            shift = bitInByte;
        } else {
            shift = 7 - bitInByte;
        }
        if (bit == 1) {
            data[byteNumber] = (byte) (data[byteNumber] | (1 << shift));
        }
    }
}
