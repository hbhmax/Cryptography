import java.util.Arrays;

public class FeistelNetwork implements SymmetricCipher {
    private KeyExpander keyExpander;
    private EncryptionTransformation roundFunction;
    private int blockSize;
    private byte[][] roundKeys;

    public FeistelNetwork(KeyExpander keyExpander, EncryptionTransformation roundFunction, int blockSize) {
        this.keyExpander = keyExpander;
        this.roundFunction = roundFunction;
        this.blockSize = blockSize;
    }

    public void setKey(byte[] key) {
        roundKeys = keyExpander.generateRoundKeys(key);
    }

    public int getBlockSize() {
        return blockSize;
    }

    public byte[] encrypt(byte[] block) {
        return runRounds(block, false);
    }

    public byte[] decrypt(byte[] block) {
        return runRounds(block, true);
    }

    private byte[] runRounds(byte[] block, boolean reverseKeys) {
        if (roundKeys == null) {
            throw new IllegalStateException("Key is not set");
        }
        if (block.length != blockSize) {
            throw new IllegalArgumentException("Wrong block size: " + block.length);
        }

        int half = blockSize / 2;
        byte[] left = Arrays.copyOfRange(block, 0, half);
        byte[] right = Arrays.copyOfRange(block, half, blockSize);
        int rounds = roundKeys.length;

        for (int i = 0; i < rounds; i++) {
            byte[] roundKey;
            if (reverseKeys) {
                roundKey = roundKeys[rounds - 1 - i];
            } else {
                roundKey = roundKeys[i];
            }
            byte[] f = roundFunction.transform(right, roundKey);
            byte[] newRight = Util.xor(left, f);
            left = right;
            right = newRight;
        }

        byte[] result = new byte[blockSize];
        System.arraycopy(right, 0, result, 0, half);
        System.arraycopy(left, 0, result, half, half);
        return result;
    }
}
