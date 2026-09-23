package interfaces;

public interface KeyExpander {
    byte[][] generateRoundKeys(byte[] key);
}
