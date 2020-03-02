package de.cqrity.pdfsigner;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.*;
import java.security.*;
import java.util.Calendar;

public class PdfSigner {

    public void signDocument(File in, FileOutputStream out) throws IOException {
        PDDocument doc = PDDocument.load(in);

        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
        signature.setName("Hannes Molsen setName");
        signature.setLocation("Scharbeutz setLoc");
        signature.setReason("Testing setReason");
        signature.setSignDate(Calendar.getInstance());

        doc.addSignature(signature);;
        ExternalSigningSupport externalSigningSupport = doc.saveIncrementalForExternalSigning(out);
        ExternalSignatureDummy signatureDummy = new ExternalSignatureDummy();

        byte[] cmsSignature = signatureDummy.signByDocument(externalSigningSupport.getContent());
        externalSigningSupport.setSignature(cmsSignature);
    }

    public void signDocumentByHash(File in, FileOutputStream out) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        PDDocument doc = PDDocument.load(in);

        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
        signature.setName("Hannes Molsen setName");
        signature.setLocation("Scharbeutz setLoc");
        signature.setReason("Testing setReason");
        signature.setSignDate(Calendar.getInstance());

        doc.addSignature(signature);;
        ExternalSigningSupport externalSigningSupport = doc.saveIncrementalForExternalSigning(out);
        ExternalSignatureDummy signatureDummy = new ExternalSignatureDummy();

        InputStream contentStream = externalSigningSupport.getContent();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
        byte[] digest = md.digest(IOUtils.toByteArray(new FileInputStream(in)));

        byte[] cmsSignature = signatureDummy.signByHash(digest);
        externalSigningSupport.setSignature(cmsSignature);
    }


}
