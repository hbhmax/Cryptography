public class DEAL implements SymmetricCipher {
    private FeistelNetwork network;

    public DEAL() {
        network = new FeistelNetwork(new DealKeyExpander(), new DesAdapter(), 16);
    }

    public void setKey(byte[] key) {
        network.setKey(key);
    }

    public int getBlockSize() {
        return 16;
    }

    public byte[] encrypt(byte[] block) {
        return network.encrypt(block);
    }

    public byte[] decrypt(byte[] block) {
        return network.decrypt(block);
    }
}
