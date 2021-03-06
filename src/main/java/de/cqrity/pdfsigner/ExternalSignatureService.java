package de.cqrity.pdfsigner;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ExternalSignatureService {

    /*
    Keystore generation
    ~/Documents/pdfsigner$ keytool -genkeypair -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -storepass 123456 -storetype pkcs12 -alias hannes -validity 365 -keystore hannes.p12
        What is your first and last name?
          [Unknown]:  Hannes Molsen
        What is the name of your organizational unit?
          [Unknown]:
        What is the name of your organization?
          [Unknown]:  Software Security
        What is the name of your City or Locality?
          [Unknown]:  Scharbeutz
        What is the name of your State or Province?
          [Unknown]:  SH
        What is the two-letter country code for this unit?
          [Unknown]:  DE
        Is CN=Hannes Molsen, OU=Unknown, O=Software Security, L=Scharbeutz, ST=SH, C=DE correct?
          [no]:  yes

     */
    public static final String ALIAS = "hannes";
    public static final char[] PASSWORD = "123456".toCharArray();

    private KeyStore keyStore;
    private Certificate[] certificateChain;
    private final CMSSignedDataGenerator gen;
    private X509Certificate signerCert;
    private ContentSigner sha256Signer;

    public ExternalSignatureService() throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, OperatorCreationException, CMSException {
        keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("hannes.p12"), PASSWORD);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(ALIAS, PASSWORD);
        certificateChain = keyStore.getCertificateChain(ALIAS);
        signerCert = (X509Certificate) certificateChain[0];

        sha256Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);

        gen =  new CMSSignedDataGenerator();
        gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

    }

    public String getKeyOwner() throws KeyStoreException {
        return keyStore.aliases().nextElement();
    }

    public byte[] signByPdfContent(InputStream content) throws IOException, CertificateEncodingException, CMSException, OperatorCreationException {
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha256Signer, signerCert));
        gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
        CMSProcessableInputStream msg = new CMSProcessableInputStream(content);

        CMSSignedData signedData = gen.generate(msg, false);
        return signedData.getEncoded();
    }

    public byte[] signByPdfContentDigest(byte[] hash) throws IOException, CertificateEncodingException, OperatorCreationException, CMSException {
        Attribute attr = new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(hash)));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(attr);

        SignerInfoGeneratorBuilder builder = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(v)));

        gen.addSignerInfoGenerator(builder.build(sha256Signer, new JcaX509CertificateHolder(signerCert)));

        CMSSignedData signedData = gen.generate(new CMSAbsentContent(), false);
        return signedData.getEncoded();

    }
}
