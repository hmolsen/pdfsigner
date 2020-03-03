package de.cqrity.pdfsigner;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class PdfWriteTest {

    private File unsignedPdfSource;

    @Before
    public void setUp() {
        unsignedPdfSource = new File("testdoc.pdf");
    }

    @Test
    public final void outputPdfSignedByDocument() throws IOException, CertificateException, CMSException, OperatorCreationException {
        File signedPdfTarget = new File("testdoc_signed.pdf");

        PdfSigner pdfSigner = new PdfSigner(unsignedPdfSource, signedPdfTarget);
        pdfSigner.signDocumentByContent();

        Assert.assertTrue(signatureIsValidOfDocument(signedPdfTarget));
    }

    @Test
    public final void outputPdfSignedByHash() throws IOException, NoSuchAlgorithmException, CertificateException, CMSException, OperatorCreationException, NoSuchProviderException {
        File signedPdfTarget = new File("testdoc_signed_by_hash.pdf");

        PdfSigner pdfSigner = new PdfSigner(unsignedPdfSource, signedPdfTarget);
        pdfSigner.signDocumentByContentDigest();

        Assert.assertTrue(signatureIsValidOfDocument(signedPdfTarget));
    }

    @SuppressWarnings("unchecked")
    private boolean signatureIsValidOfDocument(File signedPdfFile) throws IOException, CertificateException, CMSException, OperatorCreationException {
        X509Certificate signerCert = readSignerCert();

        byte[] signatureAsBytes = readSignatureAsBytesFromPdfFile(signedPdfFile);
        byte[] signedContentAsBytes = readSignedContentAsBytesFromPdfFile(signedPdfFile);

        CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedContentAsBytes), signatureAsBytes);
        SignerInformation signerInfo = cmsSignedData.getSignerInfos().getSigners().iterator().next();
        SignerId signerInfoSID = signerInfo.getSID();
        X509CertificateHolder cert = (X509CertificateHolder) cmsSignedData.getCertificates().getMatches(signerInfoSID).iterator().next();
        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert);

        return signerInfo.verify(verifier);
    }

    private byte[] readSignatureAsBytesFromPdfFile(File signedPdfFile) throws IOException {
        PDDocument signedDoc = PDDocument.load(new FileInputStream(signedPdfFile));
        List<PDSignature> signatures = signedDoc.getSignatureDictionaries();

        Assert.assertFalse(signatures.isEmpty());
        Assert.assertEquals(1, signatures.size());

        PDSignature signature = signatures.get(0);

        signature.getFilter();

        return signature.getContents(new FileInputStream(signedPdfFile));
    }

    private byte[] readSignedContentAsBytesFromPdfFile(File signedPdfFile) throws IOException {
        PDDocument signedDoc = PDDocument.load(new FileInputStream(signedPdfFile));
        PDSignature signature = signedDoc.getLastSignatureDictionary();
        return signature.getSignedContent(new FileInputStream(signedPdfFile));
    }

    private X509Certificate readSignerCert() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream certContainer = new FileInputStream("hannes.p7c");
        Collection<? extends Certificate> certificates = cf.generateCertificates(certContainer);
        Iterator<? extends Certificate> iterator = certificates.iterator();
        return (X509Certificate) iterator.next();
    }
}
