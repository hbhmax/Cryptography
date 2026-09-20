import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DesAdapter implements EncryptionTransformation {
    private Map<String, DES> knownKeys = new ConcurrentHashMap<>();

    public byte[] transform(byte[] block, byte[] roundKey) {
        String name = Util.toHex(roundKey);
        DES des = knownKeys.get(name);
        if (des == null) {
            des = new DES();
            des.setKey(roundKey);
            knownKeys.put(name, des);
        }
        return des.encrypt(block);
    }
}
