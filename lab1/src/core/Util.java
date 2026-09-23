package core;

public class Util {

    public static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static int getBit(byte[] data, int index) {
        int byteNumber = index / 8;
        int bitInByte = index % 8;
        return (data[byteNumber] >> (7 - bitInByte)) & 1;
    }

    public static byte[] fromText(String text, int size) {
        byte[] textBytes = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] result = new byte[size];
        if (textBytes.length == 0) {
            return result;
        }
        for (int i = 0; i < size; i++) {
            result[i] = textBytes[i % textBytes.length];
        }
        return result;
    }

    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(String.format("%02X", data[i]));
        }
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            String part = hex.substring(i * 2, i * 2 + 2);
            result[i] = (byte) Integer.parseInt(part, 16);
        }
        return result;
    }
}
