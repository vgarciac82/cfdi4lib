package com.angelsoft.sat.cfdi.v4;

import com.angelsoft.sat.common.CfdCommon;

import java.util.HashMap;
import java.util.Map;

public abstract class CFDv4 extends CfdCommon {

    protected static final Map<String, String> PREFIXES =
            Map.of("http://www.w3.org/2001/XMLSchema-instance", "xsi",
                   "http://www.sat.gob.mx/cfd/4", "cfdi");

    protected final Map<String, String> localPrefixes = new HashMap<>(PREFIXES);

    @Override
    public Map<String, String> getLocalPrefixes() {
        return localPrefixes;
    }

    @Override
    protected String getDigestAlgorithm() {
        return "SHA256withRSA";
    }
}
