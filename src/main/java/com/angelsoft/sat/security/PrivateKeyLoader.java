package com.angelsoft.sat.security;

import com.angelsoft.sat.exceptions.KeyException;
import org.apache.commons.ssl.PKCS8Key;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class PrivateKeyLoader implements KeyLoader {

    private PrivateKey key;

    @SuppressWarnings("unchecked")
    public PrivateKey getKey() {
        return key;
    }

    public PrivateKeyLoader(String privateKeyLocation, String keyPassword) {
        this.setPrivateKey(privateKeyLocation, keyPassword);
    }

    public PrivateKeyLoader(InputStream privateKeyInputStream, String keyPassword) {
        this.setPrivateKey(privateKeyInputStream, keyPassword);
    }

    public void setPrivateKey(String privateKeyLocation, String keyPassword) {
        try (InputStream privateKeyInputStream = new FileInputStream(privateKeyLocation)) {
            this.setPrivateKey(privateKeyInputStream, keyPassword);
        } catch (FileNotFoundException fnfe) {
            throw new KeyException("La ubicación del archivo de la llave privada es incorrecta", fnfe);
        } catch (IOException ioe) {
            throw new KeyException("No se pudo leer la llave privada", ioe);
        }
    }

    public void setPrivateKey(InputStream privateKeyInputStream, String keyPassword) {
        byte[] privateKeyByte = this.extractProtectedPrivateKey(privateKeyInputStream, keyPassword);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        try {
            this.key = KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);
        } catch (GeneralSecurityException gse) {
            throw new KeyException(
                "Error al obtener la información del certificado debido a su codificación",
                gse
            );
        }
    }

    private byte[] extractProtectedPrivateKey(InputStream privateKeyInputStream, String keyPassword) {
        try {
            if (keyPassword == null || keyPassword.isEmpty()) {
                // Java 9+: sin Guava
                return privateKeyInputStream.readAllBytes();
            } else {
                return new PKCS8Key(privateKeyInputStream, keyPassword.toCharArray()).getDecryptedBytes();
            }
        } catch (GeneralSecurityException e) {
            throw new KeyException("La contraseña del certificado no es correcta", e);
        } catch (IOException ioe) {
            throw new KeyException("No se pudo leer la llave privada", ioe);
        }
    }
}
