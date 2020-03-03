package de.cqrity.pdfsigner;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Calendar;

public class PdfSigner {

    public static final String SIGNER_NAME = "Hannes Molsen";
    public static final String SIGN_LOCATION = "Scharbeutz";
    public static final String SIGN_REASON = "Testing";
    public static final Calendar SIGN_DATE = Calendar.getInstance();

    private final ExternalSigningSupport externalSigningSupport;
    private ExternalSignatureService externalSignatureService = new ExternalSignatureService();

    public PdfSigner(File unsignedPdfSource, File signedPdfTarget) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, CMSException, OperatorCreationException {
        PDDocument doc = PDDocument.load(unsignedPdfSource);
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
        signature.setName(SIGNER_NAME);
        signature.setLocation(SIGN_LOCATION);
        signature.setReason(SIGN_REASON);
        signature.setSignDate(SIGN_DATE);
        doc.addSignature(signature);
        externalSigningSupport = doc.saveIncrementalForExternalSigning(new FileOutputStream(signedPdfTarget));
    }

    public void signDocumentByContent() throws IOException, CertificateEncodingException, OperatorCreationException, CMSException {
        InputStream pdfContentStream = externalSigningSupport.getContent();

        byte[] cmsSignature = externalSignatureService.signByPdfContent(pdfContentStream);

        externalSigningSupport.setSignature(cmsSignature);
    }

    public void signDocumentByContentDigest() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, CertificateEncodingException, OperatorCreationException, CMSException {
        InputStream pdfContentStream = externalSigningSupport.getContent();

        byte[] pdfContentDigest = getContentDigest(pdfContentStream);

        byte[] cmsSignature = externalSignatureService.signByPdfContentDigest(pdfContentDigest);

        externalSigningSupport.setSignature(cmsSignature);
    }

    private byte[] getContentDigest(InputStream pdfContentStream) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
        return md.digest(IOUtils.toByteArray(pdfContentStream));
    }


}
