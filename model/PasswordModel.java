package edu.cwru.passwordmanager.model;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;


public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    // !!! DO NOT CHANGE - VERY IMPORTANT FOR GRADING !!!
    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    // Decrypt this token to check the master password.
    private static String verifyString = "cookies";

    private void loadPasswords() {
        requireKey();
        try (BufferedReader reader = Files.newBufferedReader(passwordFile.toPath())) {
            reader.readLine(); // Skip the salt and verification token.
            String line;
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split(separator, -1);
                passwords.add(new Password(fields[0], decryptPassword(fields[1])));
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    static public void initializePasswordFile(String password) throws IOException {
        try {
            passwordFileSalt = generateSalt();
            passwordFileKey = generateKey(password, passwordFileSalt);
            String header = Base64.getEncoder().encodeToString(passwordFileSalt)
                    + separator + encryptPassword(verifyString) + "\n";
            Files.writeString(passwordFile.toPath(), header, StandardOpenOption.CREATE_NEW);
            passwordFilePassword = password;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    static public boolean verifyPassword(String password) {
        passwordFilePassword = password; // DO NOT CHANGE

        passwordFileKey = null;
        try (BufferedReader reader = Files.newBufferedReader(passwordFile.toPath())) {
            String[] fields = reader.readLine().split(separator, -1);
            if (fields.length != 2) {
                return false;
            }
            passwordFileSalt = Base64.getDecoder().decode(fields[0]);
            passwordFileKey = generateKey(password, passwordFileSalt);
            boolean correct = verifyString.equals(decryptPassword(fields[1]));
            if (!correct) {
                passwordFileKey = null;
            }
            return correct;
        } catch (Exception e) {
            passwordFileKey = null;
            return false;
        }
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        List<Password> updated = new ArrayList<>(passwords);
        updated.remove(index);
        saveFile(updated);
        passwords.remove(index);
    }

    public void updatePassword(Password password, int index) {
        validateLabel(password);
        List<Password> updated = new ArrayList<>(passwords);
        updated.set(index, password);
        saveFile(updated);
        passwords.set(index, password);
    }

    public void addPassword(Password password) {
        validateLabel(password);
        List<Password> updated = new ArrayList<>(passwords);
        updated.add(password);
        saveFile(updated);
        passwords.add(password);
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static byte[] generateKey(String password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    private static String encryptPassword(String password) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(passwordFileKey, "AES"),
                new GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
        byte[] result = ByteBuffer.allocate(iv.length + encrypted.length)
                .put(iv).put(encrypted).array();
        return Base64.getEncoder().encodeToString(result);
    }

    private static String decryptPassword(String password) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(password);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(passwordFileKey, "AES"),
                new GCMParameterSpec(128, data, 0, 12));
        return new String(cipher.doFinal(data, 12, data.length - 12), StandardCharsets.UTF_8);
    }

    private static void requireKey() {
        if (passwordFileKey == null) {
            throw new IllegalStateException("Unlock the password file first");
        }
    }

    private static void validateLabel(Password password) {
        String label = password.getLabel();
        if (label.contains(separator) || label.contains("\n") || label.contains("\r")) {
            throw new IllegalArgumentException("Labels cannot contain tabs or line breaks");
        }
    }

    private void saveFile(List<Password> updated) {
        requireKey();
        try {
            String header;
            try (BufferedReader reader = Files.newBufferedReader(passwordFile.toPath())) {
                header = reader.readLine();
            }
            StringBuilder content = new StringBuilder(header).append('\n');
            for (Password password : updated) {
                content.append(password.getLabel()).append(separator)
                        .append(encryptPassword(password.getPassword())).append('\n');
            }
            Files.writeString(passwordFile.toPath(), content.toString());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
