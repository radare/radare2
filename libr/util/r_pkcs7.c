#include <stdlib.h>
#include <string.h>
#include <r_util.h>

bool r_pkcs7_parse_certificaterevocationlists (RPKCS7CertificateRevocationLists *crls, RASN1Object *object) {
	ut32 i;
	if (!crls && !object) {
		return false;
	}
	if (object->list.length > 0) {
		crls->elements = (RX509CertificateRevocationList **) calloc (object->list.length, sizeof (RX509CertificateRevocationList*));
		if (!crls->elements) {
			return false;
		}
		crls->length = object->list.length;
		for (i = 0; i < crls->length; ++i) {
			crls->elements[i] = r_x509_parse_crl (object->list.objects[i]);
		}
	}
	return true;
}

void r_pkcs7_free_certificaterevocationlists (RPKCS7CertificateRevocationLists *crls) {
	ut32 i;
	if (crls) {
		for (i = 0; i < crls->length; ++i) {
			r_x509_free_crl (crls->elements[i]);
			crls->elements[i] = NULL;
		}
		free (crls->elements);
		crls->elements = NULL;
		// Used internally pkcs #7, so it should't free crls.
	}
}

bool r_pkcs7_parse_extendedcertificatesandcertificates (RPKCS7ExtendedCertificatesAndCertificates *ecac, RASN1Object *object) {
	ut32 i;
	if (!ecac && !object) {
		return false;
	}
	if (object->list.length > 0) {
		ecac->elements = (RX509Certificate **) calloc (object->list.length, sizeof (RX509Certificate*));
		if (!ecac->elements) {
			return false;
		}
		ecac->length = object->list.length;
		for (i = 0; i < ecac->length; ++i) {
			ecac->elements[i] = r_x509_parse_certificate (object->list.objects[i]);
		}
	}
	return true;
}

void r_pkcs7_free_extendedcertificatesandcertificates (RPKCS7ExtendedCertificatesAndCertificates *ecac) {
	ut32 i;
	if (ecac) {
		for (i = 0; i < ecac->length; ++i) {
			r_x509_free_certificate (ecac->elements[i]);
			ecac->elements[i] = NULL;
		}
		free (ecac->elements);
		ecac->elements = NULL;
		// Used internally pkcs #7, so it should't free ecac.
	}
}

bool r_pkcs7_parse_digestalgorithmidentifier (RPKCS7DigestAlgorithmIdentifiers *dai, RASN1Object *object) {
	ut32 i;
	if (!dai && !object) {
		return false;
	}
	if (object->list.length > 0) {
		dai->elements = (RX509AlgorithmIdentifier **) calloc (object->list.length, sizeof (RX509AlgorithmIdentifier*));
		if (!dai->elements) {
			return false;
		}
		dai->length = object->list.length;
		for (i = 0; i < dai->length; ++i) {
			// r_x509_parse_algorithmidentifier returns bool,
			// so i have to allocate before calling the function
			dai->elements[i] = (RX509AlgorithmIdentifier *) malloc (sizeof (RX509AlgorithmIdentifier));
			//should i handle invalid memory? the function checks the pointer
			//or it should return if dai->elements[i] == NULL ?
			if (dai->elements[i]) {
				//Memset is needed to initialize to 0 the structure and avoid garbage.
				memset (dai->elements[i], 0, sizeof (RX509AlgorithmIdentifier));
				r_x509_parse_algorithmidentifier (dai->elements[i], object->list.objects[i]);
			}
		}
	}
	return true;
}

void r_pkcs7_free_digestalgorithmidentifier (RPKCS7DigestAlgorithmIdentifiers *dai) {
	ut32 i;
	if (dai) {
		for (i = 0; i < dai->length; ++i) {
			if (dai->elements[i]) {
				r_x509_free_algorithmidentifier (dai->elements[i]);
				// r_x509_free_algorithmidentifier doesn't free the pointer
				// because on x509 the original use was internal.
				free (dai->elements[i]);
				dai->elements[i] = NULL;
			}
		}
		free (dai->elements);
		dai->elements = NULL;
		// Used internally pkcs #7, so it should't free dai.
	}
}

bool r_pkcs7_parse_contentinfo (RPKCS7ContentInfo* ci, RASN1Object *object) {
	if (!ci || !object || object->list.length < 1) {
		return false;
	}

	ci->contentType = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	if (object->list.length == 2) {
		ci->content = object->list.objects[1];
		object->list.objects[1] = NULL;
	}

	return true;
}

void r_pkcs7_free_contentinfo (RPKCS7ContentInfo* ci) {
	if (ci) {
		r_asn1_free_object (ci->content);
		r_asn1_free_string (ci->contentType);
		// Used internally pkcs #7, so it should't free ci.
	}
}

bool r_pkcs7_parse_issuerandserialnumber (RPKCS7IssuerAndSerialNumber* iasu, RASN1Object *object) {
	if (!iasu || !object || object->list.length != 2) {
		return false;
	}

	r_x509_parse_name (&iasu->issuer, object->list.objects[0]);
	iasu->serialNumber = object->list.objects[1];
	object->list.objects[1] = NULL;

	return true;
}

void r_pkcs7_free_issuerandserialnumber (RPKCS7IssuerAndSerialNumber* iasu) {
	if (iasu) {
		r_x509_free_name (&iasu->issuer);
		r_asn1_free_object (iasu->serialNumber);
		// Used internally pkcs #7, so it should't free iasu.
	}
}

/*
	RX509AlgorithmIdentifier digestEncryptionAlgorithm;
	RASN1Object *encryptedDigest;
	RASN1Object *unauthenticatedAttributes; //Optional type ??
} RPKCS7SignerInfo;
 */

bool r_pkcs7_parse_signerinfo (RPKCS7SignerInfo* si, RASN1Object *object) {
	RASN1Object **elems;
	ut32 i;
	ut32 shift = 3;
	if (!si || !object || object->list.length < 5) {
		return false;
	}
	elems = object->list.objects;
	//Following RFC
	si->version = (ut32) elems[0]->sector[0];
	r_pkcs7_parse_issuerandserialnumber (&si->issuerAndSerialNumber, elems[1]);
	r_x509_parse_algorithmidentifier (&si->digestAlgorithm, elems[2]);
	if (shift < object->list.length && elems[shift]->class == CLASS_CONTEXT && elems[shift]->tag == 0) {
		r_pkcs7_parse_attributes (&si->authenticatedAttributes, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		r_x509_parse_algorithmidentifier (&si->digestEncryptionAlgorithm, elems[shift]);
		shift++;
	}
	if (shift < object->list.length) {
		si->encryptedDigest = elems[shift];
		elems[shift] = NULL;
		shift++;
	}
	if (shift < object->list.length && elems[shift]->class == CLASS_CONTEXT && elems[shift]->tag == 1) {
		r_pkcs7_parse_attributes (&si->unauthenticatedAttributes, elems[shift]);
	}
	return true;
}

void r_pkcs7_free_signerinfo (RPKCS7SignerInfo* si) {
	if (si) {
		r_pkcs7_free_issuerandserialnumber (&si->issuerAndSerialNumber);
		r_x509_free_algorithmidentifier (&si->digestAlgorithm);
		r_pkcs7_free_attributes (&si->authenticatedAttributes);
		r_x509_free_algorithmidentifier (&si->digestEncryptionAlgorithm);
		r_asn1_free_object(si->encryptedDigest);
		r_pkcs7_free_attributes (&si->unauthenticatedAttributes);
		free (si);
	}
}

bool r_pkcs7_parse_signerinfos (RPKCS7SignerInfos *ss, RASN1Object *object) {
	ut32 i;
	if (!ss && !object) {
		return false;
	}
	if (object->list.length > 0) {
		ss->elements = (RPKCS7SignerInfo **) calloc (object->list.length, sizeof (RPKCS7SignerInfo*));
		if (!ss->elements) {
			return false;
		}
		ss->length = object->list.length;
		for (i = 0; i < ss->length; ++i) {
			// r_pkcs7_parse_signerinfo returns bool,
			// so i have to allocate before calling the function
			ss->elements[i] = (RPKCS7SignerInfo *) malloc (sizeof (RPKCS7SignerInfo));
			//should i handle invalid memory? the function checks the pointer
			//or it should return if si->elements[i] == NULL ?
			if (ss->elements[i]) {
				//Memset is needed to initialize to 0 the structure and avoid garbage.
				memset (ss->elements[i], 0, sizeof (RPKCS7SignerInfo));
				r_pkcs7_parse_signerinfo (ss->elements[i], object->list.objects[i]);
			}
		}
	}
	return true;
}

void r_pkcs7_free_signerinfos (RPKCS7SignerInfos *ss) {
	ut32 i;
	if (ss) {
		for (i = 0; i < ss->length; ++i) {
			r_pkcs7_free_signerinfo (ss->elements[i]);
			//Free the ptr, since isn't done by the function
			free (ss->elements[i]);
			ss->elements[i] = NULL;
		}
		free (ss->elements);
		ss->elements = NULL;
		// Used internally pkcs #7, so it should't free si.
	}
}

bool r_pkcs7_parse_signeddata (RPKCS7SignedData *sd, RASN1Object *object) {
	RASN1Object **elems;
	ut32 shift = 3;
	if (!sd || !object || object->list.length < 4) {
		return false;
	}
	memset (sd, 0, sizeof (RPKCS7SignedData));
	elems = object->list.objects;
	//Following RFC
	sd->version = (ut32) elems[0]->sector[0];
	r_pkcs7_parse_digestalgorithmidentifier (&sd->digestAlgorithms, elems[1]);
	r_pkcs7_parse_contentinfo (&sd->contentInfo, elems[2]);
	//Optional
	if (shift < object->list.length && elems[shift]->class == CLASS_CONTEXT && elems[shift]->tag == 0) {
		r_pkcs7_parse_extendedcertificatesandcertificates (&sd->certificates, elems[shift]);
		shift++;
	}
	//Optional
	if (shift < object->list.length && elems[shift]->class == CLASS_CONTEXT && elems[shift]->tag == 1) {
		r_pkcs7_parse_certificaterevocationlists (&sd->crls, elems[shift]);
		shift++;
	}
	if (shift < object->list.length)
		r_pkcs7_parse_signerinfos (&sd->signerinfos, elems[shift]);
	return true;
}

void r_pkcs7_free_signeddata (RPKCS7SignedData* sd) {
	if (sd) {
		r_pkcs7_free_digestalgorithmidentifier (&sd->digestAlgorithms);
		r_pkcs7_free_contentinfo (&sd->contentInfo);
		r_pkcs7_free_extendedcertificatesandcertificates (&sd->certificates);
		r_pkcs7_free_certificaterevocationlists (&sd->crls);
		// Used internally pkcs #7, so it should't free sd.
	}
}

RPKCS7Container *r_pkcs7_parse_container (const ut8 *buffer, ut32 length) {
	RASN1Object *object;
	RPKCS7Container *container;
	if (!buffer || !length) {
		return NULL;
	}
	container = (RPKCS7Container*) malloc (sizeof (RPKCS7Container));
	if (!container) {
		return NULL;
	}
	memset (container, 0, sizeof (RPKCS7Container));
	object = r_asn1_create_object (buffer, length);
	if (!object || object->list.length != 2 && object->list.objects[1]->list.length != 1) {
		free (container);
		return NULL;
	}
	container->contentType = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	r_pkcs7_parse_signeddata (&container->signedData, object->list.objects[1]->list.objects[0]);
	r_asn1_free_object (object);
	return container;
}

void r_pkcs7_free_container (RPKCS7Container* container) {
	if (container) {
		r_asn1_free_string (container->contentType);
		r_pkcs7_free_signeddata (&container->signedData);
		free (container);
	}
}

RPKCS7Attribute* r_pkcs7_parse_attribute (RASN1Object *object) {
	RPKCS7Attribute* attribute;
	if (!object || object->list.length < 1) {
		return NULL;
	}
	attribute = (RPKCS7Attribute*) malloc (sizeof (RPKCS7Attribute));
	if (!attribute) {
		return NULL;
	}
	memset (attribute, 0, sizeof (RPKCS7Attribute));
	attribute->oid = r_asn1_stringify_oid (object->list.objects[0]->sector, object->list.objects[0]->length);
	if (object->list.length == 2) {
		attribute->data = object->list.objects[1];
		object->list.objects[1] = NULL;
	}

	return attribute;
}

void r_pkcs7_free_attribute (RPKCS7Attribute* attribute) {
	if (attribute) {
		r_asn1_free_object (attribute->data);
		r_asn1_free_string (attribute->oid);
		free (attribute);
	}
}

bool r_pkcs7_parse_attributes (RPKCS7Attributes* attributes, RASN1Object *object) {
	ut32 i;
	if (!attributes || !object || !object->list.length) {
		return false;
	}

	attributes->length = object->list.length;
	if (attributes->length > 0) {
		attributes->elements = (RPKCS7Attribute**) calloc (attributes->length, sizeof (RPKCS7Attribute*));
		if (!attributes->elements) {
			attributes->length = 0;
			return false;
		}
		memset (attributes->elements, 0, attributes->length * sizeof (RPKCS7Attribute*));

		for (i = 0; i < object->list.length; ++i) {
			attributes->elements[i] = r_pkcs7_parse_attribute (object->list.objects[i]);
		}
	}
	return true;
}

void r_pkcs7_free_attributes (RPKCS7Attributes* attributes) {
	ut32 i;
	if (attributes) {
		for (i = 0; i < attributes->length; ++i) {
			r_pkcs7_free_attribute (attributes->elements[i]);
		}
		free (attributes->elements);
		attributes->elements = NULL;
		// Used internally pkcs #7, so it should't free attributes.
	}
}
