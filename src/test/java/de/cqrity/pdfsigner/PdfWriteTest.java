package de.cqrity.pdfsigner;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class PdfWriteTest {

    @Test
    public final void pdfFileCanBeRead() throws IOException {
        PdfSigner signer = new PdfSigner();
        File in = new File("testdoc.pdf");
        FileOutputStream out = new FileOutputStream("testdoc_signed.pdf");
        signer.signDocument(in, out);
    }
}
