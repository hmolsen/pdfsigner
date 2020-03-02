package de.cqrity.pdfsigner;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
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
        byte[] cmsSignature = signatureDummy.sign(externalSigningSupport.getContent());
        externalSigningSupport.setSignature(cmsSignature);

    }


}
