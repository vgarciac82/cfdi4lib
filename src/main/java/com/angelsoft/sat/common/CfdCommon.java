package com.angelsoft.sat.common;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.util.JAXBSource;
import org.w3c.dom.Document;
import org.xml.sax.ErrorHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Result;
import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Versión afinada para batch:
 *  - Caches estáticas (JAXBContext, Schema, XSLT Templates).
 *  - Pre-scan con StAX del root para decidir contextos (sin crear String gigantes).
 *  - Sin dependencias externas (Guava/commons-io).
 * Mantiene la API esperada por CFDv4*.
 */
public abstract class CfdCommon implements CfdInterface {

    // =========================
    //   CACHÉS ESTÁTICAS (JVM)
    // =========================
    private static final ConcurrentHashMap<String, JAXBContext> CTX_CACHE   = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Templates>   XSLT_CACHE  = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Schema>      SCH_CACHE   = new ConcurrentHashMap<>();

    // Detectar atributo Version case-insensitive
    private static final Pattern VERSION_ATTR = Pattern.compile("(?i)(?<=\\bversion=\")([^\"]+)");

    // =========================
    //   FACTORÍA XSLT (inyectable)
    // =========================
    private TransformerFactory tf;

    @Override
    public void setTransformerFactory(TransformerFactory tf) {
        this.tf = tf;
    }

    // =========================
    //   API ABSTRACTA (de CfdInterface)
    // =========================
    protected abstract String getDigestAlgorithm();

    // =========================
    //   CARGA / VALIDACIÓN / SELLO
    // =========================

    /**
     * Carga un comprobante desde InputStream:
     * - Pre-scan con StAX para decidir contextos y crear JAXBContext (desde caché).
     * - Unmarshal con Reader UTF-8 sin convertir a String todo el XML (salvo necesidad).
     */
    protected Object load(InputStream in, String[] addendas) throws Exception {
        // Leemos en memoria UNA vez para poder hacer pre-scan y unmarshal sin depender de mark/reset
        byte[] data = readAll(in);

        JAXBContext context = getFileContext(new ByteArrayInputStream(data), addendas);
        var u = context.createUnmarshaller();

        try (Reader reader = new InputStreamReader(new ByteArrayInputStream(data), StandardCharsets.UTF_8)) {
            return u.unmarshal(reader);
        }
    }

    /**
     * Valida contra todos los XSDs reportados por getXSD(), con cache de Schema por firma.
     */
    public void validar(ErrorHandler handler) throws Exception {
        String[] xsds = getXSD();
        if (xsds == null || xsds.length == 0) return;

        final String sig = String.join("|", xsds);
        Schema schema = SCH_CACHE.computeIfAbsent(sig, s -> {
            try {
                SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                Source[] sources = new Source[xsds.length];
                for (int i = 0; i < xsds.length; i++) {
                    InputStream is = getClass().getResourceAsStream(xsds[i]);
                    if (is == null) {
                        throw new IllegalStateException("XSD no encontrado en classpath: " + xsds[i]);
                    }
                    sources[i] = new StreamSource(is);
                }
                return sf.newSchema(sources);
            } catch (Exception e) {
                throw new RuntimeException("Error construyendo Schema para firma: " + s, e);
            }
        });

        Validator validator = schema.newValidator();
        if (handler != null) {
            validator.setErrorHandler(handler);
        }
        validator.validate(getJAXBSource());
    }

    public void verificar() throws Exception {
        byte[] cbs = Base64.getDecoder().decode(getCertificadoString());
        try (InputStream is = new ByteArrayInputStream(cbs)) {
            X509Certificate cert = com.angelsoft.sat.security.factory.KeyLoaderFactory
                    .createInstance(com.angelsoft.sat.security.KeyLoaderEnumeration.PUBLIC_KEY_LOADER, is)
                    .getKey();
            verificar(cert);
        }
    }

    private void verificar(X509Certificate cert) throws Exception {
        byte[] signature = Base64.getDecoder().decode(getSelloString());
        byte[] bytes = getOriginalBytes();
        Signature sig = Signature.getInstance(getDigestAlgorithm());
        sig.initVerify(cert);
        sig.update(bytes);
        if (!sig.verify(signature)) {
            throw new Exception("Invalid signature");
        }
    }

    public void guardar(File out, Boolean formatted) throws Exception {
        try (OutputStream os = new FileOutputStream(out)) {
            guardar(os, formatted);
        }
    }

    public void guardar(OutputStream out, Boolean formatted) throws Exception {
        if (formatted == null) formatted = Boolean.TRUE;

        Marshaller m = createMarshaller();
        m.setProperty("org.glassfish.jaxb.namespacePrefixMapper",
                new NamespacePrefixMapperImpl(getLocalPrefixes()));
        m.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, formatted);
        m.setProperty(Marshaller.JAXB_SCHEMA_LOCATION, String.join(" ", getSchemaLocation()));

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             Writer writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {

            writer.write(XML_HEADER);
            m.marshal(getComprobanteDocument(), writer);

            String xml = baos.toString(StandardCharsets.UTF_8);
            // Limpiezas específicas (se mantienen para compatibilidad)
            if (xml.contains("http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigital.xsd")) {
                xml = xml
                        .replace(" http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigital.xsd", "")
                        .replace("<tfd:TimbreFiscalDigital",
                                "<tfd:TimbreFiscalDigital xsi:schemaLocation=\"http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigital.xsd\" xmlns:tfd=\"http://www.sat.gob.mx/TimbreFiscalDigital\"");
            } else if (xml.contains("http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigitalv11.xsd")) {
                xml = xml
                        .replace(" http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigitalv11.xsd", "")
                        .replace("<tfd:TimbreFiscalDigital",
                                "<tfd:TimbreFiscalDigital xsi:schemaLocation=\"http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigitalv11.xsd\" xmlns:tfd=\"http://www.sat.gob.mx/TimbreFiscalDigital\"");
            }
            out.write(xml.getBytes(StandardCharsets.UTF_8));
        }
    }

    public String getCadenaOriginal() throws Exception {
        return new String(getOriginalBytes(), StandardCharsets.UTF_8);
    }

    // =========================
    //   CONTEXTOS / JAXBContext
    // =========================

    /**
     * Construye (y cachea) un JAXBContext en base a:
     *  - Contexto base (getBaseContext)
     *  - Addendas
     *  - Namespaces detectados en el root del XML (StAX)
     */
    protected JAXBContext getFileContext(InputStream in, String[] addendas) throws IOException, JAXBException {
        // 1) Detecta namespaces y (si se encuentra) la versión en el root
        DetectedRoot dr = detectRootNamespaces(in);

        // 2) Construye lista de contextos (paquetes) determinística
        List<String> contexts = new ArrayList<>();
        contexts.add(getBaseContext());                       // base primero
        if (addendas != null && addendas.length > 0) {
            contexts.addAll(Arrays.asList(addendas));
        }

        // match por namespace URI usando el mapa estático
        for (var e : FILE_NAMESPACE_MAP.entrySet()) {
            String key = e.getKey();        // ej: "ecc:com.angelsoft.sat.common.ecb10"
            String nsUri = e.getValue();    // ej: "http://www.sat.gob.mx/ecc"
            if (dr.namespaces.contains(nsUri)) {
                String pkg = key.substring(key.indexOf(':') + 1);
                String prefix = key.substring(0, key.indexOf(':'));
                defineContexts(contexts, prefix, pkg, nsUri);
            }
        }

        // Firmar para caché (dedup + orden)
        String signature = contextSignature(contexts);
        return CTX_CACHE.computeIfAbsent(signature, sig -> {
            try {
                return JAXBContext.newInstance(sig);
            } catch (JAXBException ex) {
                throw new RuntimeException("Error creando JAXBContext para: " + sig, ex);
            }
        });
    }

    /**
     * Variante por objeto (usada por CFDv4 cuando ya tiene el "comprobante").
     */
    protected JAXBContext getContext(Object comprobante, String[] addendas) throws JAXBException {
        final List<String> contexts = new ArrayList<>();
        contexts.add(getBaseContext());
        if (addendas != null && addendas.length > 0) {
            contexts.addAll(Arrays.asList(addendas));
        }
        defineComprobanteContext(comprobante, contexts);
        String signature = contextSignature(contexts);
        return CTX_CACHE.computeIfAbsent(signature, sig -> {
            try {
                return JAXBContext.newInstance(sig);
            } catch (JAXBException ex) {
                throw new RuntimeException("Error creando JAXBContext para: " + sig, ex);
            }
        });
    }

    /**
     * Dada una pareja (prefix, package, nsUri) añade:
     *  - prefix → nsUri a los prefijos locales
     *  - paquete JAXB a la lista de contextos
     *  - schemaLocation derivado (si el XSD está en recursos)
     */
    private void defineContexts(List<String> contexts, String ns, String pkg, String url) {
        Arrays.stream(getXSD())
                .filter(xsd -> {
                    String needle = url.substring(url.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
                    return xsd.toLowerCase(Locale.ROOT).contains(needle);
                })
                .filter(xsd -> !xsd.contains("/catalogo/") && !xsd.contains("/catalogos/"))
                .findAny()
                .ifPresent(xsd -> {
                    String schemaLocation = url + " " + xsd.replace("/xsd/common", "http://www.sat.gob.mx/sitio_internet/cfd");
                    addNamespace(url, ns);
                    contexts.add(pkg);
                    addSchemaLocation(schemaLocation);
                });
    }

    protected void defineComprobanteContext(Object c, List<String> contexts) {
        FILE_NAMESPACE_MAP.entrySet().stream()
                .filter(entry -> {
                    String pkg = entry.getKey().substring(entry.getKey().indexOf(':') + 1);
                    if (c != null && c.getClass().getPackageName().equalsIgnoreCase(pkg)) return true;
                    if (c instanceof org.w3c.dom.Element el) {
                        return entry.getValue().equalsIgnoreCase(el.getNamespaceURI());
                    }
                    return false;
                })
                .findAny()
                .ifPresent(entry -> {
                    String ns = entry.getKey().substring(0, entry.getKey().indexOf(':'));
                    String pkg = entry.getKey().substring(entry.getKey().indexOf(':') + 1);
                    defineContexts(contexts, ns, pkg, entry.getValue());
                });
    }

    private static String contextSignature(List<String> ctxs) {
        // base + addendas + detectados → únicos + ordenados determinísticamente
        return ctxs.stream().filter(Objects::nonNull).distinct().sorted().reduce((a, b) -> a + ":" + b).orElse("");
    }

    // =========================
    //   XSLT / CADENA ORIGINAL
    // =========================

    private byte[] getOriginalBytes() throws Exception {
        JAXBSource in = getJAXBSource();
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             Writer writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {

            Result out = new StreamResult(writer);
            Transformer t = obtainTransformer();
            t.transform(in, out);
            return baos.toByteArray();
        }
    }

    byte[] getOriginalBytes(InputStream in) throws IOException, TransformerException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Source source = new StreamSource(in);
            Result out = new StreamResult(baos);
            Transformer t = obtainTransformer();
            t.transform(source, out);
            return baos.toByteArray();
        }
    }

    private Transformer obtainTransformer() {
        final String xsltPath = getXSLT();
        if (xsltPath == null) {
            throw new IllegalStateException("Ruta XSLT no definida (getXSLT() retornó null)");
        }
        Templates tpl = XSLT_CACHE.computeIfAbsent(xsltPath, p -> {
            try (InputStream is = getClass().getResourceAsStream(p)) {
                if (is == null) {
                    throw new IllegalStateException("XSLT no encontrado en classpath: " + p);
                }
                TransformerFactory factory = (tf != null) ? tf : secureTransformerFactory();
                // Si tienes un URIResolver custom, configúralo en 'tf' y llámame con setTransformerFactory(tf)
                return factory.newTemplates(new StreamSource(is));
            } catch (Exception e) {
                throw new RuntimeException("Error compilando XSLT: " + p, e);
            }
        });
        return tpl.newTransformer();
    }

    private static TransformerFactory secureTransformerFactory() {
        TransformerFactory f = TransformerFactory.newInstance();
        try {
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (Exception ignore) { /* algunos impls no soportan */ }
        return f;
    }

    // =========================
    //   UTILIDADES
    // =========================

    protected void addNamespace(String uri, String prefix) {
        getLocalPrefixes().put(uri, prefix);
    }

    protected Document getDocument() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.newDocument();
    }

    protected String getSignature(PrivateKey key) throws Exception {
        byte[] bytes = getOriginalBytes();
        Signature sig = Signature.getInstance(getDigestAlgorithm());
        sig.initSign(key);
        sig.update(bytes);
        byte[] signed = sig.sign();
        return Base64.getEncoder().encodeToString(signed);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            baos.write(buf, 0, n);
        }
        return baos.toByteArray();
    }

    private static final class DetectedRoot {
        final Set<String> namespaces = new HashSet<>();
        String version;
    }

    /**
     * Lee solo el elemento raíz con StAX para obtener namespaces y la "Version".
     */
    private static DetectedRoot detectRootNamespaces(InputStream in) {
        DetectedRoot dr = new DetectedRoot();
        try {
            XMLInputFactory f = XMLInputFactory.newFactory();
            f.setProperty(XMLInputFactory.IS_COALESCING, Boolean.TRUE);
            XMLStreamReader r = f.createXMLStreamReader(in, StandardCharsets.UTF_8.name());

            while (r.hasNext()) {
                int ev = r.next();
                if (ev == XMLStreamConstants.START_ELEMENT) {
                    // ns del propio elemento
                    if (r.getNamespaceURI() != null) {
                        dr.namespaces.add(r.getNamespaceURI());
                    }
                    // ns declarados en el root
                    for (int i = 0; i < r.getNamespaceCount(); i++) {
                        String uri = r.getNamespaceURI(i);
                        if (uri != null) dr.namespaces.add(uri);
                    }
                    // atributos: busca Version (case-insensitive)
                    for (int i = 0; i < r.getAttributeCount(); i++) {
                        String local = r.getAttributeLocalName(i);
                        if (local != null && local.equalsIgnoreCase("version")) {
                            dr.version = r.getAttributeValue(i);
                        }
                    }
                    break; // con el root basta
                }
            }
            r.close();
        } catch (Exception ignore) {
            // Fallback: si algo falla, devolvemos colección vacía y sin versión; arriba hay degradación.
        }
        return dr;
    }

    // ===========================================================
    //  M A P E O   D E   N A M E S P A C E S   →   P A Q U E T E S
    //  (inmutable, usado para decidir contextos desde el root)
    // ===========================================================
    private static final Map<String, String> FILE_NAMESPACE_MAP;
    static {
        Map<String, String> m = new LinkedHashMap<>();

        // clave: "<prefijo>:<paquete JAXB>", valor: "namespace URI"
        // --- CFDI 4.0 ---
        m.put("cfdi:com.angelsoft.sat.cfd._40", "http://www.sat.gob.mx/cfd/4");

        // --- Complementos comunes (los que declaraste en xjcGeneration) ---
        m.put("ecc:com.angelsoft.sat.common.ecb10", "http://www.sat.gob.mx/ecc");
        m.put("implocal10:com.angelsoft.sat.common.implocal10", "http://www.sat.gob.mx/implocal");
        m.put("tfd:com.angelsoft.sat.common.TimbreFiscalDigital10", "http://www.sat.gob.mx/TimbreFiscalDigital");
        m.put("tfd11:com.angelsoft.sat.common.TimbreFiscalDigital11", "http://www.sat.gob.mx/TimbreFiscalDigital");
        m.put("donat11:com.angelsoft.sat.common.donat11", "http://www.sat.gob.mx/donat");
        m.put("nomina12:com.angelsoft.sat.common.nomina12", "http://www.sat.gob.mx/nomina12");
        m.put("nomina11:com.angelsoft.sat.common.nomina11", "http://www.sat.gob.mx/nomina11");
        m.put("cfdiregistrofiscal10:com.angelsoft.sat.common.cfdiregistrofiscal10", "http://www.sat.gob.mx/registrofiscal");
        m.put("pagos20:com.angelsoft.sat.common.Pagos20", "http://www.sat.gob.mx/Pagos20");
        m.put("ecc12:com.angelsoft.sat.common.EstadoDeCuentaCombustible12", "http://www.sat.gob.mx/ecc");
        m.put("consumodecombustibles11:com.angelsoft.sat.common.consumodecombustibles11", "http://www.sat.gob.mx/ConsumoDeCombustibles11");
        // Catálogos
        m.put("catCFDI:com.angelsoft.sat.common.catalogos", "http://www.sat.gob.mx/sitio_internet/cfd/catalogos");
        m.put("catNomina:com.angelsoft.sat.common.catalogos.Nomina", "http://www.sat.gob.mx/sitio_internet/cfd/catalogos/Nomina");
        m.put("catPagos:com.angelsoft.sat.common.catalogos.Pagos", "http://www.sat.gob.mx/sitio_internet/cfd/catalogos/Pagos");
        m.put("catCombustible:com.angelsoft.sat.common.catalogos.Combustible", "http://www.sat.gob.mx/sitio_internet/cfd/catalogos/Combustible");
        // (opcionales si los usas)
        m.put("iedu10:com.angelsoft.sat.common.iedu10", "http://www.sat.gob.mx/iedu");
        m.put("divisas10:com.angelsoft.sat.common.divisas10", "http://www.sat.gob.mx/divisas");

        FILE_NAMESPACE_MAP = Collections.unmodifiableMap(m);
    }
}
