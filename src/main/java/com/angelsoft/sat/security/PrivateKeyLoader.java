package com.angelsoft.sat.security;


import com.google.common.io.ByteStreams;
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
        InputStream privateKeyInputStream;
        try {
            privateKeyInputStream = new FileInputStream(privateKeyLocation);
        } catch (FileNotFoundException fnfe) {
            throw new KeyException("La ubicación del archivo de la llave privada es incorrecta", fnfe.getCause());
        }
        this.setPrivateKey(privateKeyInputStream, keyPassword);
    }

    public void setPrivateKey(InputStream privateKeyInputStream, String keyPassword) {
        byte[] privateKeyByte = this.extractProtectedPrivateKey(privateKeyInputStream, keyPassword);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        try {
            this.key = KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);
        } catch (GeneralSecurityException gse) {
            throw new KeyException(
                    "Error al obtener la información del certificado debido a su codificación",
                    gse.getCause());
        }
    }

    private byte[] extractProtectedPrivateKey(InputStream privateKeyInputStream, String keyPassword) {
        byte[] bytes;
        try {
            if (keyPassword == null) {
                bytes = ByteStreams.toByteArray(privateKeyInputStream);
            } else {
                bytes = new PKCS8Key(privateKeyInputStream, keyPassword.toCharArray()).getDecryptedBytes();
            }
        } catch (GeneralSecurityException e) {
            throw new KeyException("La contraseña del certificado no es correcta", e.getCause());
        } catch (IOException ioe) {
            throw new KeyException(ioe.getMessage(), ioe.getCause());
        }
        return bytes;
    }

}
