package com.angelsoft.sat.common;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.util.JAXBSource;
import com.angelsoft.sat.security.KeyLoaderEnumeration;
import com.angelsoft.sat.security.factory.KeyLoaderFactory;
import com.angelsoft.sat.util.StreamUtils;
import org.w3c.dom.Document;
import org.xml.sax.ErrorHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class CfdCommon implements CfdInterface {

    protected final Map<List<String>, JAXBContext> contextMap = new HashMap<>();

    private TransformerFactory tf;

    protected abstract String getDigestAlgorithm();

    public void setTransformerFactory(TransformerFactory tf) {
        this.tf = tf;
        tf.setURIResolver(new URIResolverImpl());
    }

    protected Object load(InputStream in, String[] addendas) throws Exception {
        List<InputStream> copies = StreamUtils.copyStream(in, 2);
        JAXBContext context = getFileContext(copies.get(0), addendas);
        Unmarshaller u = context.createUnmarshaller();
        try (Reader reader = new InputStreamReader(copies.get(1), StandardCharsets.UTF_8)) {
            return u.unmarshal(reader);
        }
    }

    public void validar(ErrorHandler handler) throws Exception {
        SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Source[] schemas = new Source[getXSD().length];
        for (int i = 0; i < getXSD().length; i++) {
            schemas[i] = new StreamSource(getClass().getResourceAsStream(getXSD()[i]));
        }
        Schema schema = sf.newSchema(schemas);
        Validator validator = schema.newValidator();
        if (handler != null) {
            validator.setErrorHandler(handler);
        }
        validator.validate(getJAXBSource());
    }

    public void verificar() throws Exception {
        byte[] cbs = Base64.getDecoder().decode(getCertificadoString());
        try (InputStream is = new ByteArrayInputStream(cbs)) {
            X509Certificate cert = KeyLoaderFactory.createInstance(
                    KeyLoaderEnumeration.PUBLIC_KEY_LOADER,
                    is
            ).getKey();
            verificar(cert);
        }
    }

    public void guardar(File out, Boolean formatted) throws Exception {
        try (OutputStream outputStream = new FileOutputStream(out)) {
            guardar(outputStream, formatted);
        }
    }

    public void guardar(OutputStream out, Boolean formatted) throws Exception {
        if (formatted == null) formatted = true;
        Marshaller m = createMarshaller();
        m.setProperty("org.glassfish.jaxb.namespacePrefixMapper", new NamespacePrefixMapperImpl(getLocalPrefixes()));
        m.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, formatted);
        m.setProperty(Marshaller.JAXB_SCHEMA_LOCATION, String.join(" ", getSchemaLocation()));
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); Writer writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {
            writer.write(XML_HEADER);
            m.marshal(getComprobanteDocument(), writer);
            String xml = baos.toString("UTF-8").replace("xmlns:tfd=\"http://www.sat.gob.mx/TimbreFiscalDigital\" ", "");
            if (xml.contains("http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigital.xsd")) {
                xml = xml
                        .replace(" http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigital.xsd", "")
                        .replace("<tfd:TimbreFiscalDigital", "<tfd:TimbreFiscalDigital xsi:schemaLocation=\"http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigital.xsd\" xmlns:tfd=\"http://www.sat.gob.mx/TimbreFiscalDigital\"");
            } else if (xml.contains("http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigitalv11.xsd")) {
                xml = xml
                        .replace(" http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigitalv11.xsd", "")
                        .replace("<tfd:TimbreFiscalDigital", "<tfd:TimbreFiscalDigital xsi:schemaLocation=\"http://www.sat.gob.mx/TimbreFiscalDigital http://www.sat.gob.mx/sitio_internet/cfd/TimbreFiscalDigital/TimbreFiscalDigitalv11.xsd\" xmlns:tfd=\"http://www.sat.gob.mx/TimbreFiscalDigital\"");
            }
            out.write(xml.getBytes(StandardCharsets.UTF_8));
        }
    }

    public String getCadenaOriginal() throws Exception {
        byte[] bytes = getOriginalBytes();
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private void defineContexts(List<String> contexts, String ns, String pkg, String url) {
        Arrays.stream(getXSD())
                .filter(xsd -> xsd.toLowerCase(Locale.ROOT).contains(url.substring(url.lastIndexOf("/") + 1).toLowerCase(Locale.ROOT)))
                .filter(xsd -> !xsd.contains("/catalogo/") && !xsd.contains("/catalogos/"))
                .findAny().ifPresent(value -> {
                    String schemaLocation = url + " " + value.replace("/xsd/common", "http://www.sat.gob.mx/sitio_internet/cfd");
                    addNamespace(url, ns);
                    contexts.add(pkg);
                    addSchemaLocation(schemaLocation);
                });
    }

    protected void defineComprobanteContext(Object c, List<String> contexts) {
        getFileNamespaceMap().entrySet().stream()
                .filter(entry -> {
                    if (entry.getKey().split(":")[1].equalsIgnoreCase(c.getClass().getPackageName())) return true;
                    return c instanceof org.w3c.dom.Element && entry.getValue().equalsIgnoreCase(((org.w3c.dom.Element) c).getNamespaceURI());
                })
                .findAny().ifPresent(entry -> {
                    String ns = entry.getKey().split(":")[0];
                    String pkg = entry.getKey().split(":")[1];
                    defineContexts(contexts, ns, pkg, entry.getValue());
                });
    }

    protected void addNamespace(String uri, String prefix) {
        getLocalPrefixes().put(uri, prefix);
    }

    protected Document getDocument() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.newDocument();
    }

    //Verifica textualmente el XML con el XSD (Funciona cuando queremos validar un XML que NO fue creado con esta librería
    public void verificar(InputStream in) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] cbs = decoder.decode(getCertificadoString());

        X509Certificate cert = KeyLoaderFactory.createInstance(
                KeyLoaderEnumeration.PUBLIC_KEY_LOADER,
                new ByteArrayInputStream(cbs)
        ).getKey();

        byte[] signature = decoder.decode(getSelloString());
        byte[] bytes = getOriginalBytes(in);
        Signature sig = Signature.getInstance(getDigestAlgorithm());
        sig.initVerify(cert);
        sig.update(bytes);
        boolean bool = sig.verify(signature);
        if (!bool) {
            throw new Exception("Invalid signature.");
        }
    }

    private void verificar(X509Certificate cert) throws Exception {
        String sigStr = getSelloString();
        byte[] signature = Base64.getDecoder().decode(sigStr);
        byte[] bytes = getOriginalBytes();
        Signature sig = Signature.getInstance(getDigestAlgorithm());
        sig.initVerify(cert);
        sig.update(bytes);
        boolean bool = sig.verify(signature);
        if (!bool) {
            throw new Exception("Invalid signature");
        }
    }

    //Funciona en conjunto con: verificar(InputStream in)
    byte[] getOriginalBytes(InputStream in) throws IOException, TransformerException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Source source = new StreamSource(in);
            Result out = new StreamResult(baos);
            TransformerFactory factory = tf;
            if (factory == null) {
                factory = TransformerFactory.newInstance();
                factory.setURIResolver(new URIResolverImpl());
            }
            Transformer transformer = factory.newTransformer(new StreamSource(getClass().getResourceAsStream(getXSLT())));
            transformer.transform(source, out);
            return baos.toByteArray();
        }
    }

    private byte[] getOriginalBytes() throws Exception {
        JAXBSource in = getJAXBSource();
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); Writer writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {
            Result out = new StreamResult(writer);
            TransformerFactory factory = tf;
            if (factory == null) {
                factory = TransformerFactory.newInstance();
                factory.setURIResolver(new URIResolverImpl());
            }
            Transformer transformer = factory.newTransformer(new StreamSource(getClass().getResourceAsStream(getXSLT())));
            transformer.transform(in, out);
            return baos.toByteArray();
        }
    }

    protected String getSignature(PrivateKey key) throws Exception {
        byte[] bytes = getOriginalBytes();
        byte[] signed;
        Signature sig = Signature.getInstance(getDigestAlgorithm());
        sig.initSign(key);
        sig.update(bytes);
        signed = sig.sign();
        Base64.Encoder b64 = Base64.getEncoder();
        return b64.encodeToString(signed);
    }

    //***DO NOT EDIT*** FROM HERE
    private Map<String, String> getFileNamespaceMap() {
        Map<String, String> namespaceMap = new HashMap<>();
        // (tu mapeo existente queda igual)
        namespaceMap.put("ecc:com.angelsoft.sat.common.ecc", "http://www.sat.gob.mx/ecc");
        // ... resto del bloque sin cambios ...
        namespaceMap.put("consumodecombustibles11:com.angelsoft.sat.common.consumodecombustibles11", "http://www.sat.gob.mx/ConsumoDeCombustibles11");
        return namespaceMap;
    }
    //***DO NOT EDIT*** TO HERE

    protected JAXBContext getFileContext(InputStream in, String[] addendas) throws IOException, JAXBException {
        final List<String> contexts = new ArrayList<>();
        contexts.add(getBaseContext());
        contexts.addAll(Arrays.asList(addendas));
        final String xml = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> namespaceMap = getFileNamespaceMap();
        namespaceMap.entrySet().stream()
                .filter(entry -> xml.toLowerCase(Locale.ROOT).contains(entry.getValue().toLowerCase(Locale.ROOT)))
                .forEach(entry -> {
                    String ns = entry.getKey().split(":")[0];
                    String pkg = entry.getKey().split(":")[1];
                    if (!xml.contains("<" + ns + ":")) return;
                    if (namespaceMap.entrySet().stream().filter(e -> e.getValue().equalsIgnoreCase(entry.getValue())).count() > 1) {
                        int startIndex = xml.indexOf("<" + ns);
                        Matcher versionMatcher = Pattern.compile("(?<=[V|v]ersion=\")((.)*?)(?=\")", Pattern.CASE_INSENSITIVE).matcher(xml.substring(startIndex));
                        if (versionMatcher.find()) {
                            String version = versionMatcher.group().replace(".", "");
                            if (!entry.getKey().contains(version)) return;
                        }
                    }
                    defineContexts(contexts, ns, pkg, entry.getValue());
                });
        return JAXBContext.newInstance(String.join(":", contexts));
    }
}
