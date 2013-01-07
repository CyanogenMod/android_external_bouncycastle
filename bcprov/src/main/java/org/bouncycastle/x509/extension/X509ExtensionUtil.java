package org.bouncycastle.x509.extension;

import java.io.IOException;
// BEGIN android-added
import java.net.InetAddress;
import java.net.UnknownHostException;
// END android-added
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
// BEGIN android-added
import org.bouncycastle.asn1.x509.X509Name;
// END android-added


public class X509ExtensionUtil
{
    public static ASN1Primitive fromExtensionValue(
        byte[]  encodedValue) 
        throws IOException
    {
        ASN1OctetString octs = (ASN1OctetString)ASN1Primitive.fromByteArray(encodedValue);
        
        return ASN1Primitive.fromByteArray(octs.getOctets());
    }

    public static Collection getIssuerAlternativeNames(X509Certificate cert)
            throws CertificateParsingException
    {
        byte[] extVal = cert.getExtensionValue(X509Extension.issuerAlternativeName.getId());

        return getAlternativeNames(extVal);
    }

    public static Collection getSubjectAlternativeNames(X509Certificate cert)
            throws CertificateParsingException
    {        
        byte[] extVal = cert.getExtensionValue(X509Extension.subjectAlternativeName.getId());

        return getAlternativeNames(extVal);
    }

    private static Collection getAlternativeNames(byte[] extVal)
        throws CertificateParsingException
    {
        if (extVal == null)
        {
            // BEGIN android-changed
            return null;
            // END android-changed
        }
        try
        {
            Collection temp = new ArrayList();
            Enumeration it = DERSequence.getInstance(fromExtensionValue(extVal)).getObjects();
            while (it.hasMoreElements())
            {
                GeneralName genName = GeneralName.getInstance(it.nextElement());
                List list = new ArrayList();
                // BEGIN android-changed
                list.add(Integer.valueOf(genName.getTagNo()));
                // END android-changed
                switch (genName.getTagNo())
                {
                case GeneralName.ediPartyName:
                case GeneralName.x400Address:
                case GeneralName.otherName:
                    // BEGIN android-changed
                    list.add(genName.getEncoded());
                    // END android-changed
                    break;
                case GeneralName.directoryName:
                    // BEGIN android-changed
                    list.add(X509Name.getInstance(genName.getName()).toString(true,
                            X509Name.DefaultSymbols));
                    // END android-changed
                    break;
                case GeneralName.dNSName:
                case GeneralName.rfc822Name:
                case GeneralName.uniformResourceIdentifier:
                    list.add(((ASN1String)genName.getName()).getString());
                    break;
                case GeneralName.registeredID:
                    list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
                    break;
                case GeneralName.iPAddress:
                    // BEGIN android-changed
                    byte[] addrBytes = DEROctetString.getInstance(genName.getName()).getOctets();
                    final String addr;
                    try {
                        addr = InetAddress.getByAddress(addrBytes).getHostAddress();
                    } catch (UnknownHostException e) {
                        continue;
                    }
                    list.add(addr);
                    // END android-changed
                    break;
                default:
                    throw new IOException("Bad tag number: " + genName.getTagNo());
                }

                temp.add(list);
            }
            // BEGIN android-added
            if (temp.size() == 0) {
                return null;
            }
            // END android-added
            return Collections.unmodifiableCollection(temp);
        }
        catch (Exception e)
        {
            throw new CertificateParsingException(e.getMessage());
        }
    }
}
