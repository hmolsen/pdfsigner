package de.cqrity.pdfsigner;

import org.junit.Assert;
import org.junit.Test;

import java.security.KeyStoreException;

public class ExternalSignatureDummyTest {

    @Test
    public final void canCreateSigner() throws KeyStoreException {
        ExternalSignatureDummy extSig = new ExternalSignatureDummy();
        Assert.assertEquals("hannes", extSig.getKeyOwner());
    }
}
