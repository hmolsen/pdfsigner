package de.cqrity.pdfsigner;

import org.junit.Assert;
import org.junit.Test;

import java.security.KeyStoreException;

public class ExternalSignatureServiceTest {

    @Test
    public final void canCreateSigner() throws KeyStoreException {
        ExternalSignatureService extSig = new ExternalSignatureService();
        Assert.assertEquals("hannes", extSig.getKeyOwner());
    }
}
