package com.angelsoft.sat.security.factory;

import com.angelsoft.sat.security.KeyLoader;
import com.angelsoft.sat.security.KeyLoaderEnumeration;
import com.angelsoft.sat.security.PrivateKeyLoader;
import com.angelsoft.sat.security.PublicKeyLoader;

import java.io.InputStream;

@SuppressWarnings("DuplicatedCode")
public class KeyLoaderFactory {

    public static KeyLoader createInstance(KeyLoaderEnumeration keyLoaderEnumeration, String keyLocation, String... keyPassword) {
        KeyLoader keyLoader;
        if (keyLoaderEnumeration == KeyLoaderEnumeration.PRIVATE_KEY_LOADER) {
            keyLoader = new PrivateKeyLoader(keyLocation, keyPassword == null ? null : keyPassword[0]);
        } else if (keyLoaderEnumeration == KeyLoaderEnumeration.PUBLIC_KEY_LOADER) {
            keyLoader = new PublicKeyLoader(keyLocation);
        } else {
            keyLoader = null;
        }
        return keyLoader;
    }

    public static KeyLoader createInstance(KeyLoaderEnumeration keyLoaderEnumeration, InputStream keyInputStream, String... keyPassword) {
        KeyLoader keyLoader;
        if (keyLoaderEnumeration == KeyLoaderEnumeration.PRIVATE_KEY_LOADER) {
            keyLoader = new PrivateKeyLoader(keyInputStream, keyPassword == null ? null : keyPassword[0]);
        } else if (keyLoaderEnumeration == KeyLoaderEnumeration.PUBLIC_KEY_LOADER) {
            keyLoader = new PublicKeyLoader(keyInputStream);
        } else {
            keyLoader = null;
        }
        return keyLoader;
    }

}
