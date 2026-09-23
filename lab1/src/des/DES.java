package des;

import interfaces.SymmetricCipher;
import feistel.FeistelNetwork;
import core.Permutation;

public class DES implements SymmetricCipher {
    private FeistelNetwork network;

    public DES() {
        network = new FeistelNetwork(new DesKeyExpander(), new DesRoundFunction(), 8);
    }

    public void setKey(byte[] key) {
        network.setKey(key);
    }

    public int getBlockSize() {
        return 8;
    }

    public byte[] encrypt(byte[] block) {
        byte[] x = Permutation.permute(block, DesTables.IP, false, 1);
        x = network.encrypt(x);
        return Permutation.permute(x, DesTables.FP, false, 1);
    }

    public byte[] decrypt(byte[] block) {
        byte[] x = Permutation.permute(block, DesTables.IP, false, 1);
        x = network.decrypt(x);
        return Permutation.permute(x, DesTables.FP, false, 1);
    }
}
