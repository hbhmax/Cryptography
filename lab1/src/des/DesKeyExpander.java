package des;

import interfaces.KeyExpander;
import core.Permutation;
import core.Util;

public class DesKeyExpander implements KeyExpander {

    public byte[][] generateRoundKeys(byte[] key) {
        if (key.length != 8) {
            throw new IllegalArgumentException("DES key must be 8 bytes");
        }

        byte[] permuted = Permutation.permute(key, DesTables.PC1, false, 1);

        int c = 0;
        int d = 0;
        for (int i = 0; i < 28; i++) {
            c = (c << 1) | Util.getBit(permuted, i);
        }
        for (int i = 28; i < 56; i++) {
            d = (d << 1) | Util.getBit(permuted, i);
        }

        byte[][] roundKeys = new byte[16][];
        for (int round = 0; round < 16; round++) {
            int shift = DesTables.SHIFTS[round];
            c = rotateLeft28(c, shift);
            d = rotateLeft28(d, shift);

            long joined = (((long) c) << 28) | d;
            byte[] joinedBytes = new byte[7];
            for (int k = 0; k < 7; k++) {
                joinedBytes[k] = (byte) (joined >> (48 - 8 * k));
            }
            roundKeys[round] = Permutation.permute(joinedBytes, DesTables.PC2, false, 1);
        }
        return roundKeys;
    }

    private int rotateLeft28(int value, int shift) {
        return ((value << shift) | (value >>> (28 - shift))) & 0x0FFFFFFF;
    }
}
