package interfaces;

public interface EncryptionTransformation {
    byte[] transform(byte[] block, byte[] roundKey);
}
