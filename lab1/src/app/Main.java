package app;

import interfaces.SymmetricCipher;
import des.DES;
import deal.DEAL;
import modes.CipherMode;
import modes.PaddingMode;
import modes.CipherContext;
import core.Util;
import core.Result;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean work = true;

        while (work) {
            System.out.println();
            System.out.println("1 - DES: check on known example and test all modes on random bytes");
            System.out.println("2 - DEAL: test all modes on random bytes");
            System.out.println("3 - DES and DEAL: test all modes on files from folder 'files'");
            System.out.println("4 - encrypt or decrypt one file");
            System.out.println("0 - exit");
            System.out.print("Your choice: ");
            String choice = scanner.nextLine().trim();

            try {
                if (choice.equals("1")) {
                    checkDesExample();
                    testRandomBytes("DES");
                } else if (choice.equals("2")) {
                    testRandomBytes("DEAL");
                } else if (choice.equals("3")) {
                    testFiles();
                } else if (choice.equals("4")) {
                    processOneFile(scanner);
                } else if (choice.equals("0")) {
                    work = false;
                } else {
                    System.out.println("Unknown choice");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e);
            }
        }
    }

    private static SymmetricCipher createCipher(String name) {
        if (name.equals("DES")) {
            return new DES();
        }
        return new DEAL();
    }

    private static int getKeySize(String name) {
        if (name.equals("DES")) {
            return 8;
        }
        return 16;
    }

    private static int getBlockSize(String name) {
        if (name.equals("DES")) {
            return 8;
        }
        return 16;
    }

    private static void checkDesExample() {
        byte[] key = Util.fromHex("133457799BBCDFF1");
        byte[] plain = Util.fromHex("0123456789ABCDEF");
        DES des = new DES();
        des.setKey(key);
        byte[] encrypted = des.encrypt(plain);
        byte[] decrypted = des.decrypt(encrypted);

        System.out.println("Known example for DES");
        System.out.println("Encrypted: " + Util.toHex(encrypted));
        System.out.println("Expected:  85E813540F0AB405");
        System.out.println("Decrypted: " + Util.toHex(decrypted));
    }

    private static void testRandomBytes(String name) {
        Random random = new Random();
        byte[] key = new byte[getKeySize(name)];
        random.nextBytes(key);
        byte[] iv = new byte[getBlockSize(name)];
        random.nextBytes(iv);

        for (CipherMode mode : CipherMode.values()) {
            for (PaddingMode padding : PaddingMode.values()) {
                byte[] data = new byte[1000 + random.nextInt(100)];
                random.nextBytes(data);
                data[data.length - 1] = 1;

                CipherContext context = new CipherContext(createCipher(name), key, mode, padding, iv);
                Result encrypted = new Result();
                Result decrypted = new Result();
                context.encrypt(data, encrypted).join();
                context.decrypt(encrypted.data, decrypted).join();

                boolean same = Arrays.equals(data, decrypted.data);
                String text = "OK";
                if (!same) {
                    text = "FAIL";
                }
                System.out.println(name + " " + mode + " " + padding + " (" + data.length + " bytes): " + text);
            }
        }
    }

    private static void testFiles() throws Exception {
        File folder = new File("files");
        if (!folder.exists()) {
            System.out.println("Folder 'files' not found");
            return;
        }
        new File("out_files").mkdirs();

        File[] list = folder.listFiles();
        String[] algorithms = {"DES", "DEAL"};

        for (File file : list) {
            if (file.isDirectory()) {
                continue;
            }
            for (String name : algorithms) {
                for (CipherMode mode : CipherMode.values()) {
                    byte[] key = Util.fromText("secret key", getKeySize(name));
                    byte[] iv = Util.fromText("init vector", getBlockSize(name));
                    CipherContext context = new CipherContext(createCipher(name), key, mode, PaddingMode.PKCS7, iv);

                    String prefix = "out_files/" + file.getName() + "." + name + "." + mode;
                    long start = System.currentTimeMillis();
                    context.encrypt(file.getPath(), prefix + ".enc").join();
                    context.decrypt(prefix + ".enc", prefix + ".dec").join();
                    long time = System.currentTimeMillis() - start;

                    byte[] original = Files.readAllBytes(Paths.get(file.getPath()));
                    byte[] result = Files.readAllBytes(Paths.get(prefix + ".dec"));
                    String text = "OK";
                    if (!Arrays.equals(original, result)) {
                        text = "FAIL";
                    }
                    System.out.println(file.getName() + " " + name + " " + mode + ": " + text + " (" + time + " ms)");
                }
            }
        }
        System.out.println("Results are in folder 'out_files'");
    }

    private static int chooseNumber(Scanner scanner, String title, Object[] values) {
        System.out.println(title);
        for (int i = 0; i < values.length; i++) {
            System.out.println((i + 1) + " - " + values[i]);
        }
        int number = Integer.parseInt(scanner.nextLine().trim());
        return number - 1;
    }

    private static void processOneFile(Scanner scanner) {
        String[] algorithms = {"DES", "DEAL"};
        String name = algorithms[chooseNumber(scanner, "Algorithm:", algorithms)];
        CipherMode mode = CipherMode.values()[chooseNumber(scanner, "Mode:", CipherMode.values())];
        PaddingMode padding = PaddingMode.values()[chooseNumber(scanner, "Padding:", PaddingMode.values())];

        System.out.print("Key (any text): ");
        String keyText = scanner.nextLine();
        System.out.print("Input file path: ");
        String inputPath = scanner.nextLine().trim();
        System.out.print("Output file path: ");
        String outputPath = scanner.nextLine().trim();

        String[] actions = {"encrypt", "decrypt"};
        int action = chooseNumber(scanner, "Action:", actions);

        byte[] key = Util.fromText(keyText, getKeySize(name));
        byte[] iv = Util.fromText("iv" + keyText, getBlockSize(name));
        CipherContext context = new CipherContext(createCipher(name), key, mode, padding, iv);

        if (action == 0) {
            context.encrypt(inputPath, outputPath).join();
        } else {
            context.decrypt(inputPath, outputPath).join();
        }
        System.out.println("Done: " + outputPath);
    }
}
