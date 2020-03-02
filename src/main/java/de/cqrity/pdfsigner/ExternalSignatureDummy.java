package de.cqrity.pdfsigner;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ExternalSignatureDummy {

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
    private String keystorePath = "hannes.p12";

    private KeyStore keyStore;
    private PrivateKey privateKey;
    private Certificate[] certificateChain;

    public ExternalSignatureDummy() {
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(keystorePath), PASSWORD);
            privateKey = (PrivateKey) keyStore.getKey(ALIAS, PASSWORD);
            certificateChain = keyStore.getCertificateChain(ALIAS);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    public String getKeyOwner() throws KeyStoreException {
        return keyStore.aliases().nextElement();
    }

    /**
     * SignatureInterface sample implementation.
     *<p>
     * This method will be called from inside of the pdfbox and create the PKCS #7 signature.
     * The given InputStream contains the bytes that are given by the byte range.
     *<p>
     * This method is for internal use only.
     *<p>
     * Use your favorite cryptographic library to implement PKCS #7 signature creation.
     * If you want to create the hash and the signature separately (e.g. to transfer only the hash
     * to an external application), read <a href="https://stackoverflow.com/questions/41767351">this
     * answer</a> or <a href="https://stackoverflow.com/questions/56867465">this answer</a>.
     *
     * @throws IOException
     */

    public byte[] sign(InputStream content) throws IOException
    {
        // cannot be done private (interface)
        try
        {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate cert = (X509Certificate) certificateChain[0];
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, cert));
            gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);
            return signedData.getEncoded();
        }
        catch (GeneralSecurityException | CMSException | OperatorCreationException e)
        {
            throw new IOException(e);
        }
    }
}
