import java.security.SecureRandom;
import java.util.Arrays;

public class Padding {

    public static byte[] addPadding(byte[] data, int blockSize, PaddingMode mode) {
        int padLength = blockSize - data.length % blockSize;
        if (mode == PaddingMode.ZEROS && padLength == blockSize) {
            padLength = 0;
        }

        byte[] result = Arrays.copyOf(data, data.length + padLength);
        int last = result.length - 1;

        if (mode == PaddingMode.ANSI_X923) {
            result[last] = (byte) padLength;
        } else if (mode == PaddingMode.PKCS7) {
            for (int i = data.length; i < result.length; i++) {
                result[i] = (byte) padLength;
            }
        } else if (mode == PaddingMode.ISO_10126) {
            byte[] random = new byte[padLength];
            new SecureRandom().nextBytes(random);
            for (int i = 0; i < padLength - 1; i++) {
                result[data.length + i] = random[i];
            }
            result[last] = (byte) padLength;
        }
        return result;
    }

    public static byte[] removePadding(byte[] data, int blockSize, PaddingMode mode) {
        if (data.length == 0) {
            return data;
        }

        if (mode == PaddingMode.ZEROS) {
            int end = data.length;
            while (end > 0 && data[end - 1] == 0) {
                end--;
            }
            return Arrays.copyOf(data, end);
        }

        int padLength = data[data.length - 1] & 0xFF;
        if (padLength < 1 || padLength > blockSize || padLength > data.length) {
            throw new IllegalArgumentException("Wrong padding (maybe wrong key or mode)");
        }

        if (mode == PaddingMode.PKCS7) {
            for (int i = data.length - padLength; i < data.length; i++) {
                if (data[i] != padLength) {
                    throw new IllegalArgumentException("Wrong PKCS7 padding");
                }
            }
        } else if (mode == PaddingMode.ANSI_X923) {
            for (int i = data.length - padLength; i < data.length - 1; i++) {
                if (data[i] != 0) {
                    throw new IllegalArgumentException("Wrong ANSI X.923 padding");
                }
            }
        }
        return Arrays.copyOf(data, data.length - padLength);
    }
}
