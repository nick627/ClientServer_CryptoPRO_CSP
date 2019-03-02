// Csptest\mycert.c

#include "utils.h"

PCCERT_CONTEXT WINAPI MyCertCreateCertificateContext(
	DWORD dwCertEncodingType,
	const BYTE *pbCertEncoded,
	DWORD cbCertEncoded) 
{
	HCERTSTORE hcs = NULL;
	int loop;
	int count;
	PCCERT_CONTEXT psc = NULL;
	PCCERT_CONTEXT pic = NULL;
	PCCERT_CONTEXT ret = NULL;
	DWORD dwf;
	const int MAXCERTCHAIN = 1000;

	__try {
		ret = CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded);
		if (ret)
			return ret;
		if (dwCertEncodingType & PKCS_7_ASN_ENCODING) {
			hcs = CryptGetMessageCertificates(PKCS_7_ASN_ENCODING, 0, 0, pbCertEncoded, cbCertEncoded);
			loop = 0;
			do {
				if (++loop > MAXCERTCHAIN) {
					// fprintf(stderr, __FILE__":%d:%s", __LINE__, "Too long certificates chain\n");
					return NULL;
				}
				// Цикл для каждого сертификата в сообщении PKCS#7
				count = 0;
				psc = NULL;
				while ((psc = CertEnumCertificatesInStore(hcs, psc)) != NULL) {
					count++;
					// Удаляем первого попавшегося issuer-а из store и повторяем цикл
					dwf = 0;
					if ((pic = CertGetIssuerCertificateFromStore(hcs, psc, NULL, &dwf)) != NULL) {
						CertDeleteCertificateFromStore(pic);
						//CertFreeCertificateContext(pic);
						pic = NULL;
						CertFreeCertificateContext(psc);
						psc = NULL;
						count = MAXCERTCHAIN;
						break;
					}
				}
			} while (count > 1);
			ret = CertEnumCertificatesInStore(hcs, NULL);
			return ret;
		}
		if (dwCertEncodingType & X509_ASN_ENCODING) {
			ret = CertCreateCertificateContext(X509_ASN_ENCODING,
				pbCertEncoded, cbCertEncoded);
			if (ret)
				return ret;
		}
	}
	__finally {
		if (pic) {
			CertFreeCertificateContext(pic);
			pic = NULL;
		}
		if (psc) {
			CertFreeCertificateContext(psc);
			psc = NULL;
		}
		if (hcs) {
			CertCloseStore(hcs, 0); // Отложенное закрытие по CertFreeCertificateContext(ret)
			hcs = NULL;
		}
	}
	return NULL;
}

//--------------------------------------------------------------------
// Функция чтения сертификата из файла

PCCERT_CONTEXT read_cert_from_file(const char *fname)
{
	BYTE *cert = NULL;
	size_t len = 0;
	PCCERT_CONTEXT ret = NULL;

	if (!get_file_data_pointer(fname, &len, &cert))
		return NULL;

	ret = MyCertCreateCertificateContext(MY_ENCODING_TYPE, cert, len);
	if (!ret) {
		return 0;
		// HandleError("CertCreateCertificateContext");
	}
	release_file_data_pointer(cert);
	return ret;
}

//--------------------------------------------------------------------

