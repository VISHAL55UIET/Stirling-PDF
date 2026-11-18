package stirling.software.SPDF.pdf.signature;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

import javax.imageio.ImageIO;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import lombok.extern.slf4j.Slf4j;

/**
 * Extracts an embedded inline image from an X.509 certificate's RFC 3709 Logotype extension (OID
 * 1.3.6.1.5.5.7.1.12) for use as a visible digital signature appearance logo.
 */
@Slf4j
public final class CertificateLogoExtractor {

    /** RFC 3709 id-pe-logotype extension OID. */
    public static final String LOGOTYPE_EXTENSION_OID = "1.3.6.1.5.5.7.1.12";

    private CertificateLogoExtractor() {}

    /**
     * Attempts to extract an inline image (e.g. {@code data:image/png;base64,...}) from the given
     * X.509 certificate. External HTTP/HTTPS URIs are intentionally ignored to avoid network
     * requests or SSRF risks during signing.
     *
     * @param cert the signer's X.509 certificate
     * @return decoded image bytes if a valid embedded logotype image is found, otherwise empty
     */
    public static Optional<byte[]> extractLogo(X509Certificate cert) {
        if (cert == null) {
            return Optional.empty();
        }
        byte[] extValue = cert.getExtensionValue(LOGOTYPE_EXTENSION_OID);
        if (extValue == null || extValue.length == 0) {
            return Optional.empty();
        }

        try (ASN1InputStream outerIn = new ASN1InputStream(extValue)) {
            ASN1Primitive outerObj = outerIn.readObject();
            if (!(outerObj instanceof ASN1OctetString octetString)) {
                return Optional.empty();
            }
            try (ASN1InputStream innerIn = new ASN1InputStream(octetString.getOctets())) {
                ASN1Primitive logotypeExtn = innerIn.readObject();
                return parseLogotypeExtn(logotypeExtn);
            }
        } catch (Exception e) {
            log.debug("Failed to parse X.509 logotype extension: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * RFC 3709 LogotypeExtn ::= SEQUENCE { communityLogos [0] EXPLICIT SEQUENCE OF LogotypeInfo
     * OPTIONAL, issuerLogo [1] EXPLICIT LogotypeInfo OPTIONAL, subjectLogo [2] EXPLICIT
     * LogotypeInfo OPTIONAL, otherLogos [3] EXPLICIT SEQUENCE OF OtherLogotypeInfo OPTIONAL }
     */
    private static Optional<byte[]> parseLogotypeExtn(ASN1Primitive primitive) {
        if (!(primitive instanceof ASN1Sequence seq)) {
            return Optional.empty();
        }

        ASN1TaggedObject communityLogosTag = null;
        ASN1TaggedObject subjectLogoTag = null;

        for (ASN1Encodable element : seq) {
            if (element instanceof ASN1TaggedObject tagged) {
                if (tagged.getTagNo() == 2) {
                    subjectLogoTag = tagged;
                } else if (tagged.getTagNo() == 0) {
                    communityLogosTag = tagged;
                }
            }
        }

        // Prefer subjectLogo ([2]) over communityLogos ([0])
        if (subjectLogoTag != null) {
            Optional<byte[]> subjectImage =
                    parseLogotypeInfo(subjectLogoTag.getBaseObject().toASN1Primitive());
            if (subjectImage.isPresent()) {
                return subjectImage;
            }
        }

        if (communityLogosTag != null) {
            ASN1Primitive communityObj = communityLogosTag.getBaseObject().toASN1Primitive();
            if (communityObj instanceof ASN1Sequence communitySeq) {
                for (ASN1Encodable item : communitySeq) {
                    Optional<byte[]> communityImage = parseLogotypeInfo(item.toASN1Primitive());
                    if (communityImage.isPresent()) {
                        return communityImage;
                    }
                }
            }
        }

        return Optional.empty();
    }

    /** LogotypeInfo ::= CHOICE { direct [0] LogotypeData, indirect [1] LogotypeReference } */
    private static Optional<byte[]> parseLogotypeInfo(ASN1Primitive primitive) {
        if (!(primitive instanceof ASN1TaggedObject tagged) || tagged.getTagNo() != 0) {
            return Optional.empty();
        }
        return parseLogotypeData(tagged.getBaseObject().toASN1Primitive());
    }

    /**
     * LogotypeData ::= SEQUENCE { image [0] SEQUENCE OF LogotypeImage OPTIONAL, audio [1] SEQUENCE
     * OF LogotypeAudio OPTIONAL }
     */
    private static Optional<byte[]> parseLogotypeData(ASN1Primitive primitive) {
        if (!(primitive instanceof ASN1Sequence dataSeq)) {
            return Optional.empty();
        }
        for (ASN1Encodable element : dataSeq) {
            if (element instanceof ASN1TaggedObject tagged && tagged.getTagNo() == 0) {
                ASN1Primitive imageSeqObj = tagged.getBaseObject().toASN1Primitive();
                if (imageSeqObj instanceof ASN1Sequence imageSeq) {
                    for (ASN1Encodable imageItem : imageSeq) {
                        Optional<byte[]> extracted =
                                parseLogotypeImage(imageItem.toASN1Primitive());
                        if (extracted.isPresent()) {
                            return extracted;
                        }
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * LogotypeImage ::= SEQUENCE { imageDetails LogotypeDetails, imageInfo LogotypeImageInfo
     * OPTIONAL } LogotypeDetails ::= SEQUENCE { mediaType IA5String, logotypeHash SEQUENCE OF
     * HashAlgAndValue, logotypeURI SEQUENCE OF IA5String }
     */
    private static Optional<byte[]> parseLogotypeImage(ASN1Primitive primitive) {
        if (!(primitive instanceof ASN1Sequence logotypeImageSeq) || logotypeImageSeq.size() == 0) {
            return Optional.empty();
        }
        ASN1Primitive detailsObj = logotypeImageSeq.getObjectAt(0).toASN1Primitive();
        if (!(detailsObj instanceof ASN1Sequence detailsSeq) || detailsSeq.size() < 3) {
            return Optional.empty();
        }
        ASN1Primitive urisObj = detailsSeq.getObjectAt(2).toASN1Primitive();
        if (!(urisObj instanceof ASN1Sequence uriSeq)) {
            return Optional.empty();
        }
        for (ASN1Encodable uriEncodable : uriSeq) {
            if (uriEncodable.toASN1Primitive() instanceof ASN1IA5String ia5) {
                Optional<byte[]> decoded = decodeDataImageUri(ia5.getString());
                if (decoded.isPresent()) {
                    return decoded;
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<byte[]> decodeDataImageUri(String uri) {
        if (uri == null) {
            return Optional.empty();
        }
        String trimmed = uri.trim();
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("data:image/")) {
            return Optional.empty();
        }
        int base64MarkerIndex = lower.indexOf(";base64,");
        if (base64MarkerIndex < 0) {
            return Optional.empty();
        }
        String base64Payload = trimmed.substring(base64MarkerIndex + ";base64,".length()).trim();
        if (base64Payload.isEmpty()) {
            return Optional.empty();
        }
        try {
            byte[] imageBytes = Base64.getDecoder().decode(base64Payload);
            if (!isValidImage(imageBytes)) {
                return Optional.empty();
            }
            return Optional.of(imageBytes);
        } catch (IllegalArgumentException e) {
            log.debug("Invalid base64 image payload in certificate logotype URI");
            return Optional.empty();
        }
    }

    private static boolean isValidImage(byte[] imageBytes) {
        if (imageBytes == null || imageBytes.length == 0) {
            return false;
        }
        try (ByteArrayInputStream bais = new ByteArrayInputStream(imageBytes)) {
            return ImageIO.read(bais) != null;
        } catch (IOException e) {
            return false;
        }
    }
}
