package des;

import interfaces.EncryptionTransformation;
import core.Permutation;
import core.Util;

public class DesRoundFunction implements EncryptionTransformation {

    public byte[] transform(byte[] block, byte[] roundKey) {
        byte[] expanded = Permutation.permute(block, DesTables.E, false, 1);
        byte[] mixed = Util.xor(expanded, roundKey);

        byte[] afterSBoxes = new byte[4];
        for (int i = 0; i < 8; i++) {
            int six = 0;
            for (int j = 0; j < 6; j++) {
                six = six * 2 + Util.getBit(mixed, i * 6 + j);
            }
            int row = ((six >> 4) & 2) | (six & 1);
            int column = (six >> 1) & 15;
            int value = DesTables.S[i][row][column];

            if (i % 2 == 0) {
                afterSBoxes[i / 2] = (byte) (afterSBoxes[i / 2] | (value << 4));
            } else {
                afterSBoxes[i / 2] = (byte) (afterSBoxes[i / 2] | value);
            }
        }

        return Permutation.permute(afterSBoxes, DesTables.P, false, 1);
    }
}
