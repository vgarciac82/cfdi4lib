package com.angelsoft.sat.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class StreamUtils {

    public static List<InputStream> copyStream(InputStream input, int copies) throws IOException {
        // lee todo el stream
        byte[] data = readAll(input);

        // quita BOM UTF-8 si viene (EF BB BF)
        if (data.length >= 3
                && (data[0] & 0xFF) == 0xEF
                && (data[1] & 0xFF) == 0xBB
                && (data[2] & 0xFF) == 0xBF) {
            data = Arrays.copyOfRange(data, 3, data.length);
        }

        List<InputStream> list = new ArrayList<>(copies);
        for (int i = 0; i < copies; i++) {
            list.add(new ByteArrayInputStream(data));
        }
        return list;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        // compatible con streams grandes (sin depender de Guava)
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            baos.write(buf, 0, n);
        }
        return baos.toByteArray();
    }
}
