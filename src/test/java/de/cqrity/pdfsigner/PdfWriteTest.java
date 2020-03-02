package de.cqrity.pdfsigner;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

public class PdfWriteTest {

    @Test
    public final void outputPdfSignedByDocument() throws IOException {
        PdfSigner signer = new PdfSigner();
        File in = new File("testdoc.pdf");
        File outFile = new File("testdoc_signed.pdf");
        if (outFile.exists()) {
            outFile.delete();
        }
        FileOutputStream out = new FileOutputStream(outFile);
        signer.signDocument(in, out);
    }
    @Test
    public final void outputPdfSignedByHash() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        PdfSigner signer = new PdfSigner();
        File in = new File("testdoc.pdf");
        FileOutputStream out = new FileOutputStream("testdoc_signed_by_hash.pdf");
        signer.signDocumentByHash(in, out);
    }
}
