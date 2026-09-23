package modes;

import interfaces.SymmetricCipher;
import core.Util;
import core.Result;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;

public class CipherContext {
    private SymmetricCipher cipher;
    private CipherMode mode;
    private PaddingMode padding;
    private byte[] iv;
    private BigInteger delta;
    private int blockSize;

    public CipherContext(SymmetricCipher cipher, byte[] key, CipherMode mode, PaddingMode padding, byte[] iv, Object... extraParams) {
        this.cipher = cipher;
        this.mode = mode;
        this.padding = padding;
        this.blockSize = cipher.getBlockSize();
        cipher.setKey(key);

        if (mode != CipherMode.ECB) {
            if (iv == null) {
                iv = new byte[blockSize];
                new SecureRandom().nextBytes(iv);
            }
            if (iv.length != blockSize) {
                throw new IllegalArgumentException("IV must be " + blockSize + " bytes");
            }
        }
        this.iv = iv;

        if (mode == CipherMode.RANDOM_DELTA) {
            if (extraParams.length > 0 && extraParams[0] instanceof Number) {
                long value = ((Number) extraParams[0]).longValue();
                delta = BigInteger.valueOf(value);
            } else {
                byte[] secondHalf = Arrays.copyOfRange(iv, blockSize / 2, blockSize);
                delta = new BigInteger(1, secondHalf);
            }
            if (delta.signum() == 0) {
                delta = BigInteger.ONE;
            }
        }
    }

    public byte[] getIv() {
        return iv;
    }

    public CompletableFuture<Void> encrypt(byte[] data, Result result) {
        return CompletableFuture.runAsync(() -> {
            result.data = encryptData(data);
        });
    }

    public CompletableFuture<Void> decrypt(byte[] data, Result result) {
        return CompletableFuture.runAsync(() -> {
            result.data = decryptData(data);
        });
    }

    public CompletableFuture<Void> encrypt(String inputPath, String outputPath) {
        return CompletableFuture.runAsync(() -> {
            try {
                byte[] data = Files.readAllBytes(Paths.get(inputPath));
                byte[] encrypted = encryptData(data);
                Files.write(Paths.get(outputPath), encrypted);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public CompletableFuture<Void> decrypt(String inputPath, String outputPath) {
        return CompletableFuture.runAsync(() -> {
            try {
                byte[] data = Files.readAllBytes(Paths.get(inputPath));
                byte[] decrypted = decryptData(data);
                Files.write(Paths.get(outputPath), decrypted);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private byte[] encryptData(byte[] data) {
        byte[] padded = Padding.addPadding(data, blockSize, padding);
        int blocks = padded.length / blockSize;
        byte[] out = new byte[padded.length];

        if (mode == CipherMode.ECB) {
            IntStream.range(0, blocks).parallel().forEach(i -> {
                putBlock(out, i, cipher.encrypt(getBlock(padded, i)));
            });
        } else if (mode == CipherMode.CBC) {
            byte[] previous = iv;
            for (int i = 0; i < blocks; i++) {
                byte[] c = cipher.encrypt(Util.xor(getBlock(padded, i), previous));
                putBlock(out, i, c);
                previous = c;
            }
        } else if (mode == CipherMode.PCBC) {
            byte[] mix = iv;
            for (int i = 0; i < blocks; i++) {
                byte[] p = getBlock(padded, i);
                byte[] c = cipher.encrypt(Util.xor(p, mix));
                putBlock(out, i, c);
                mix = Util.xor(c, p);
            }
        } else if (mode == CipherMode.CFB) {
            byte[] previous = iv;
            for (int i = 0; i < blocks; i++) {
                byte[] c = Util.xor(cipher.encrypt(previous), getBlock(padded, i));
                putBlock(out, i, c);
                previous = c;
            }
        } else if (mode == CipherMode.OFB) {
            return xorWithOfbStream(padded);
        } else if (mode == CipherMode.CTR) {
            return xorWithCounterStream(padded, BigInteger.ONE);
        } else if (mode == CipherMode.RANDOM_DELTA) {
            return xorWithCounterStream(padded, delta);
        }
        return out;
    }

    private byte[] decryptData(byte[] data) {
        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException("Encrypted data length must be a multiple of " + blockSize);
        }
        int blocks = data.length / blockSize;
        byte[] out = new byte[data.length];

        if (mode == CipherMode.ECB) {
            IntStream.range(0, blocks).parallel().forEach(i -> {
                putBlock(out, i, cipher.decrypt(getBlock(data, i)));
            });
        } else if (mode == CipherMode.CBC) {
            IntStream.range(0, blocks).parallel().forEach(i -> {
                byte[] previous = iv;
                if (i > 0) {
                    previous = getBlock(data, i - 1);
                }
                byte[] p = Util.xor(cipher.decrypt(getBlock(data, i)), previous);
                putBlock(out, i, p);
            });
        } else if (mode == CipherMode.PCBC) {
            byte[] mix = iv;
            for (int i = 0; i < blocks; i++) {
                byte[] c = getBlock(data, i);
                byte[] p = Util.xor(cipher.decrypt(c), mix);
                putBlock(out, i, p);
                mix = Util.xor(c, p);
            }
        } else if (mode == CipherMode.CFB) {
            IntStream.range(0, blocks).parallel().forEach(i -> {
                byte[] previous = iv;
                if (i > 0) {
                    previous = getBlock(data, i - 1);
                }
                byte[] p = Util.xor(getBlock(data, i), cipher.encrypt(previous));
                putBlock(out, i, p);
            });
        } else if (mode == CipherMode.OFB) {
            return Padding.removePadding(xorWithOfbStream(data), blockSize, padding);
        } else if (mode == CipherMode.CTR) {
            return Padding.removePadding(xorWithCounterStream(data, BigInteger.ONE), blockSize, padding);
        } else if (mode == CipherMode.RANDOM_DELTA) {
            return Padding.removePadding(xorWithCounterStream(data, delta), blockSize, padding);
        }

        return Padding.removePadding(out, blockSize, padding);
    }

    private byte[] xorWithOfbStream(byte[] data) {
        int blocks = data.length / blockSize;
        byte[] out = new byte[data.length];
        byte[] o = iv;
        for (int i = 0; i < blocks; i++) {
            o = cipher.encrypt(o);
            putBlock(out, i, Util.xor(getBlock(data, i), o));
        }
        return out;
    }

    private byte[] xorWithCounterStream(byte[] data, BigInteger step) {
        int blocks = data.length / blockSize;
        byte[] out = new byte[data.length];
        IntStream.range(0, blocks).parallel().forEach(i -> {
            byte[] counter = makeCounter(i, step);
            byte[] gamma = cipher.encrypt(counter);
            putBlock(out, i, Util.xor(getBlock(data, i), gamma));
        });
        return out;
    }

    private byte[] makeCounter(int blockNumber, BigInteger step) {
        BigInteger start = new BigInteger(1, iv);
        BigInteger value = start.add(step.multiply(BigInteger.valueOf(blockNumber)));
        BigInteger limit = BigInteger.ONE.shiftLeft(8 * blockSize);
        value = value.mod(limit);

        byte[] raw = value.toByteArray();
        byte[] result = new byte[blockSize];
        int count = Math.min(raw.length, blockSize);
        for (int k = 0; k < count; k++) {
            result[blockSize - 1 - k] = raw[raw.length - 1 - k];
        }
        return result;
    }

    private byte[] getBlock(byte[] data, int number) {
        return Arrays.copyOfRange(data, number * blockSize, (number + 1) * blockSize);
    }

    private void putBlock(byte[] data, int number, byte[] block) {
        System.arraycopy(block, 0, data, number * blockSize, blockSize);
    }
}
