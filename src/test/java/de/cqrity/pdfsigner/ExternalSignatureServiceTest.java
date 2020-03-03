package de.cqrity.pdfsigner;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class ExternalSignatureServiceTest {

    @Test
    public final void canCreateSigner() throws KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, IOException, CMSException, OperatorCreationException {
        ExternalSignatureService extSig = new ExternalSignatureService();
        Assert.assertEquals("hannes", extSig.getKeyOwner());
    }
}
