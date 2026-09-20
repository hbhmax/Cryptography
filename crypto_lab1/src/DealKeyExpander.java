import java.util.Arrays;

public class DealKeyExpander implements KeyExpander {
    private static final byte[] FIXED_KEY = Util.fromHex("0123456789ABCDEF");

    public byte[][] generateRoundKeys(byte[] key) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("DEAL key must be 16, 24 or 32 bytes");
        }

        int parts = key.length / 8;
        int rounds = 6;
        if (parts == 4) {
            rounds = 8;
        }

        DES des = new DES();
        des.setKey(FIXED_KEY);

        byte[][] roundKeys = new byte[rounds][];
        byte[] previous = new byte[8];

        for (int i = 0; i < rounds; i++) {
            int start = (i % parts) * 8;
            byte[] keyPart = Arrays.copyOfRange(key, start, start + 8);
            byte[] x = Util.xor(keyPart, previous);
            if (i >= parts) {
                x = Util.xor(x, makeConstant(i - parts));
            }
            roundKeys[i] = des.encrypt(x);
            previous = roundKeys[i];
        }
        return roundKeys;
    }

    private byte[] makeConstant(int power) {
        long number = 1L << power;
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++) {
            result[i] = (byte) (number >> (56 - 8 * i));
        }
        return result;
    }
}
