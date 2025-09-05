package com.angelsoft.sat.common;

import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import java.util.ArrayList;
import java.util.List;

public final class ValidationErrorHandler extends DefaultHandler {

    private final List<SAXParseException> errors = new ArrayList<>();

    public void error(SAXParseException e) {
        errors.add(e);
    }

    public List<SAXParseException> getErrors() {
        return List.copyOf(errors);
    }
}
