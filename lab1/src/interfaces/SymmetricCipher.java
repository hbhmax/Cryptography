package interfaces;

public interface SymmetricCipher {
    void setKey(byte[] key);
    byte[] encrypt(byte[] block);
    byte[] decrypt(byte[] block);
    int getBlockSize();
}
