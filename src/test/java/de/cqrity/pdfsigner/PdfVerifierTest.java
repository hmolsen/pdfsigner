package de.cqrity.pdfsigner;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.*;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static org.junit.Assert.*;

public class PdfVerifierTest {

    private File signedPdfSource;
    private File selfSignedPdfSource;
    private byte[] signedPdfFileContents;

    @Before
    public void setUp() throws IOException {
        String signedPdfSourcePath = "1585554827.pdf_swisscom_signed_aes.pdf";
        signedPdfSource = new File(signedPdfSourcePath);
        String selfSignedPdfSourcePath = "testdoc_signed_by_hash.pdf";
        selfSignedPdfSource = new File(selfSignedPdfSourcePath);
        signedPdfFileContents = Files.readAllBytes(Paths.get(signedPdfSourcePath));
    }

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Test
    public void testVerifySignatureOfSwisscomSignedPdf() throws IOException, CMSException, CertificateException, OperatorCreationException {
        PDDocument pdDocument = PDDocument.load(signedPdfSource);

        // Every signature of a PDF Document has a signature dictionary.
        // The test file has one AES signature
        List<PDSignature> signatureDictionaries = pdDocument.getSignatureDictionaries();
        assertEquals(1, signatureDictionaries.size());

        // In the signature dictonary is the "ByteRange", i.e. the range of bytes in the file
        // which are used to compute the hash, which is used for signing.
        PDSignature pdSignature = signatureDictionaries.get(0);

        // getSignedContent retrieves exactly those bytes of the document which are signed,
        // i.e., everything but the signature itself
        byte[] signedPdfContent = pdSignature.getSignedContent(signedPdfFileContents);

        // The signature is the hex representation, usually BER / DER formatted ASN.1
        byte[] signature = pdSignature.getContents(signedPdfFileContents);

        // ByteRange: [ start, begin of signature, end of signature, remaining bytes ]
        int[] byteRange = pdSignature.getByteRange();
        System.out.println("ByteRange[" + byteRange[0] + " " + byteRange[1] + " " + byteRange[2] + " " + byteRange[3] + "]");

        // Bytes used to compute signature should start at the beginning of the document
        assertEquals(0, byteRange[0]);

        // Bytes used to compute signature should end at the end of the document
        assertEquals(signedPdfFileContents.length, byteRange[2] + byteRange[3]);

        int bytesBeforeSignature = byteRange[1] - byteRange[0];
        int bytesAfterSignature = byteRange[3];

        assertEquals(bytesBeforeSignature + bytesAfterSignature, signedPdfContent.length);


        System.out.println("Signature Length: " + signature.length);

        // The signature is wrapped by the less than < and greater than > characters.
        // Therefore the size of the signedPdfContent plus the size of the signature
        // should be exactly 2 bytes less than the original document.
        // 2 characters in hex make one byte, => signature * 2
        assertEquals(signedPdfFileContents.length - 2, signedPdfContent.length + (2 * signature.length));


        // BouncyCastle wants the content bytes of the pdf to verify the signature
        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(signedPdfContent);


        CMSSignedData cmsSignedData = new CMSSignedData(cmsByteArray, signature);

        // This code is far too simple for a real verification, as it only verifies the signature against the certificate
        // provided in the ASN.1 structure itself. This could be any certificate. Just the signature needs to be correct.
        // - the trust chain up to the Swisscom Root CA needs to be verified
        // - it needs to be checked that the trusted time stamp is valid
        // - it needs to be verified that the certificate has not been revoked
        // - it needs to be verified that signature was generated when the certificate was valid
        // ...
        SignerInformation signerInfo = cmsSignedData.getSignerInfos().getSigners().iterator().next();
        SignerId signerInfoSID = signerInfo.getSID();
        X509CertificateHolder cert = (X509CertificateHolder) cmsSignedData.getCertificates().getMatches(signerInfoSID).iterator().next();
        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert);

        assertTrue(signerInfo.verify(verifier));

        // change one byte in the verified bytes
        signedPdfContent[0] += 1;

        // redo the verification
        CMSProcessableByteArray cmsByteArrayFails = new CMSProcessableByteArray(signedPdfContent);

        CMSSignedData cmsSignedDataFails = new CMSSignedData(cmsByteArrayFails, signature);

        SignerInformation signerInfoFails = cmsSignedDataFails.getSignerInfos().getSigners().iterator().next();
        SignerId signerInfoSIDFails = signerInfo.getSID();
        X509CertificateHolder certFails = (X509CertificateHolder) cmsSignedData.getCertificates().getMatches(signerInfoSIDFails).iterator().next();
        SignerInformationVerifier verifierFails = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(certFails);

        exception.expect(CMSSignerDigestMismatchException.class);
        signerInfoFails.verify(verifierFails);
    }
}