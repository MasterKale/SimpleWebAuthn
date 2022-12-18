import { verifyAttestationWithMetadata } from './verifyAttestationWithMetadata';
import { MetadataStatement } from '../metadata/mdsTypes';
import { isoBase64URL } from '../helpers/iso';

test('should verify attestation with metadata (android-safetynet)', async () => {
  const metadataStatementJSONSafetyNet: MetadataStatement = {
    legalHeader: 'https://fidoalliance.org/metadata/metadata-statement-legal-header/',
    aaguid: 'b93fd961-f2e6-462f-b122-82002247de78',
    description: 'Android Authenticator with SafetyNet Attestation',
    authenticatorVersion: 1,
    protocolFamily: 'fido2',
    schema: 3,
    upv: [{ major: 1, minor: 0 }],
    authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
    publicKeyAlgAndEncodings: ['cose'],
    attestationTypes: ['basic_full'],
    userVerificationDetails: [
      [{ userVerificationMethod: 'faceprint_internal' }],
      [{ userVerificationMethod: 'fingerprint_internal' }],
      [{ userVerificationMethod: 'passcode_internal' }],
      [{ userVerificationMethod: 'pattern_internal' }],
    ],
    keyProtection: ['hardware', 'tee'],
    isKeyRestricted: false,
    matcherProtection: ['tee'],
    attachmentHint: ['internal'],
    tcDisplay: [],
    // Truncated from 28 to 1 to reduce test execution time
    attestationRootCertificates: [
      'MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==',
    ],
    icon: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB7klEQVR4AaWPP2sUQRiHn5mdvexd/plEcvlDCi1E/EMabUWI9jaKWPoV/A7BQhAbG7t8CCUIKQQLuwhCUBsLBSUmGkLudm9n5nWHzMAego3P8Oy9s8vvfd+jzctPz2Ya+Zdbu48mG0ma8Eh8/bF3yWGGwPvV81d7+9/2lpy3Mrty7jswPPz8Yb20lQJ2iain2w9ok02aLURWstxuiHgknnrEK3GERg9poZ7s3CUxl/dvVfrntmRag9BuICJgrXfHnRvAWyJaDxXB+ezCWqX3t6e6i/ri/E1AkdBoLi/cZrL5pqeHb2yvu9RIUKfiWH95IVmmV6eucK1/j8JMIwRo6jNcX77P2vQ6ZEZ7OXreSFA93rnD3Mx6r7YfTxQKGkN4WP8eW7+bz4Z3eHEE9FFZAJXuliXVyUEfif9ZHINW+BQ5fSc+3oTjztTZRkx4LEhtfh1avBMSIkBrA+JvOAohm1AFgJGRpbOoXS/X1KXgHZE4X1Ssxpt18iYImGJiRFWWKCXkBdiR4L0QUEKamIKxhoQZm6fAdMDVjT7cQwBEYh3DSsl4A+trQTwJbUCsT5P+CodTZtYDmNJYcrEDQSChIMsVzoVQ2kLFMCCQFW4AoDbfbRDI7fIi5aAL41jtVNiQiPUjmUBOgAMCm683/ss/TaVXtx4qKMoAAAAASUVORK5CYII=',
    authenticatorGetInfo: {
      versions: ['FIDO_2_0'],
      aaguid: 'b93fd961f2e6462fb12282002247de78',
      options: { plat: true, rk: true, uv: true },
    },
  };

  // Extracted from an actual android-safetynet response
  const x5c = [
    'MIIFYDCCBEigAwIBAgIRANhcGl70B5aICQAAAAEBn/EwDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxEzARBgNVBAMTCkdUUyBDQSAxRDQwHhcNMjIwMTI1MTAwMDM0WhcNMjIwNDI1MTAwMDMzWjAdMRswGQYDVQQDExJhdHRlc3QuYW5kcm9pZC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCY5lzFcHle1DLltNJhlScnqVRsXCWz61Fo/FGKlbm4lb9c7rYzYNoLMlTXkZiK4GREvvjgwLwc7LC8M6zorFqa9j3z4m/MudCaFVtw0AUnejjVRhTbZEJik8QEbhx5azBNSp3h+G865LZ+ygDdd0VZKdq53KB9j0F8ybkdvUcSs/m3GMjWEAip4WnrDY9FLZfx+pCpANOAbTNvciiKAwOkQGDEI1FqTCuInZiHRvmifOQsOnSExIu3sW7vQcEtTbF+UZxhjbH5EvbdoEnaLM6TBJyul7tzWuj4Y4XTckvdSCnrASwsgyQ9uN9whPvAVnxGVBXIETEtUA8myP43TKsJAgMBAAGjggJwMIICbDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUqVM2UMZVAK5CyQY6FGrtSI71s2owHwYDVR0jBBgwFoAUJeIYDrJXkZQq5dRdhpCD3lOzuJIwbQYIKwYBBQUHAQEEYTBfMCoGCCsGAQUFBzABhh5odHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxZDRpbnQwMQYIKwYBBQUHMAKGJWh0dHA6Ly9wa2kuZ29vZy9yZXBvL2NlcnRzL2d0czFkNC5kZXIwHQYDVR0RBBYwFIISYXR0ZXN0LmFuZHJvaWQuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybHMucGtpLmdvb2cvZ3RzMWQ0aW50L1I3OGY1ejNqN3lnLmNybDCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB1AFGjsPX9AXmcVm24N3iPDKR6zBsny/eeiEKaDf7UiwXlAAABfpDlDAIAAAQDAEYwRAIgI45lPq05WVxIzo1UlhhSEvrIoAV5Eqt0+lVEnilXq8UCICWpGFH9D/DyfgagW3/2gEuHZZ8KGK9B9JZzBCJ+BvSeAHYAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF+kOUL4gAABAMARzBFAiEAocmVdclCD2bFPONoV21tb8GseWd2Fm3WSGqWM0wD0BsCIEetDyp5zcn58j8hRDRo/VUGtg3mv2+Y6JF4jnzBRKEQMA0GCSqGSIb3DQEBCwUAA4IBAQAInlxnIIvCKkViJe5btE6MPYAjx3GHZ1K/zltpseMRQ8bFUKMFLSSq7uNFPQr7OW3hChgLCCVoEzG4bqFuMxWb+Ht9PHtFxVXzbgJyjbvD7HSOTqk8AY1a/NQ5ujsCLSJ4Df6RdhH/OvpteP3NflUWNMIBEv0Uv1tvLEfQGW0hSbg6L/HGgAcWuL7l6/PXIEu2eL7kaGFRhI2bj4JN9YEHGnvhcGp55yB37hIx1l8U75X9hH1O6MMmzvJ05qtXCsTXQiejD0TtxTjGV+VKtpLXICpTfxNspBzCLh91ILm2pG4V9dkmEVo90tJzJI/AK6aPfogcJoBgnpS8UYwANmSC',
    'MIIFjDCCA3SgAwIBAgINAgCOsgIzNmWLZM3bmzANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAwMDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFENDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKvAqqPCE27l0w9zC8dTPIE89bA+xTmDaG7y7VfQ4c+mOWhlUebUQpK0yv2r678RJExK0HWDjeq+nLIHN1Em5j6rARZixmyRSjhIR0KOQPGBMUldsaztIIJ7O0g/82qj/vGDl//3t4tTqxiRhLQnTLXJdeB+2DhkdU6IIgx6wN7E5NcUH3Rcsejcqj8p5Sj19vBm6i1FhqLGymhMFroWVUGO3xtIH91dsgy4eFKcfKVLWK3o2190Q0Lm/SiKmLbRJ5Au4y1euFJm2JM9eB84Fkqa3ivrXWUeVtye0CQdKvsY2FkazvxtxvusLJzLWYHk55zcRAacDA2SeEtBbQfD1qsCAwEAAaOCAXYwggFyMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJeIYDrJXkZQq5dRdhpCD3lOzuJIwHwYDVR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYGCCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcwAoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsME0GA1UdIARGMEQwCAYGZ4EMAQIBMDgGCisGAQQB1nkCBQMwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAgEAIVToy24jwXUr0rAPc924vuSVbKQuYw3nLflLfLh5AYWEeVl/Du18QAWUMdcJ6o/qFZbhXkBH0PNcw97thaf2BeoDYY9Ck/b+UGluhx06zd4EBf7H9P84nnrwpR+4GBDZK+Xh3I0tqJy2rgOqNDflr5IMQ8ZTWA3yltakzSBKZ6XpF0PpqyCRvp/NCGv2KX2TuPCJvscp1/m2pVTtyBjYPRQ+QuCQGAJKjtN7R5DFrfTqMWvYgVlpCJBkwlu7+7KY3cTIfzE7cmALskMKNLuDz+RzCcsYTsVaU7Vp3xL60OYhqFkuAOOxDZ6pHOj9+OJmYgPmOT4X3+7L51fXJyRH9KfLRP6nT31D5nmsGAOgZ26/8T9hsBW1uo9ju5fZLZXVVS5H0HyIBMEKyGMIPhFWrlt/hFS28N1zaKI0ZBGD3gYgDLbiDT9fGXstpk+Fmc4olVlWPzXe81vdoEnFbr5M272HdgJWo+WhT9BYM0Ji+wdVmnRffXgloEoluTNcWzc41dFpgJu8fF3LG0gl2ibSYiCi9a6hvU0TppjJyIWXhkJTcMJlPrWx1VytEUGrX2l0JDwRjW/656r0KVB02xHRKvm2ZKI03TglLIpmVCK3kBKkKNpBNkFt8rhafcCKOb9Jx/9tpNFlQTl7B39rJlJWkR17QnZqVptFePFORoZmFzM=',
    'MIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UECxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYxOTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63ladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwSiV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351kKSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZDrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zkj5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5cuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esWCruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499iYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35EiEua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbapsZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUHMAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAyMAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIFAwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9NR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9WprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy+qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvid0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=',
  ];
  const credentialPublicKey =
    'pQECAyYgASFYIAKH2NrGZT-lUEA3tbBXR9owjW_7OnA1UqoL1UuKY_VCIlggpjeOH0xyBCpGDya55JLXXKrzyOieQN3dvG1pV-Qs-Gs';

  const verified = await verifyAttestationWithMetadata({
    statement: metadataStatementJSONSafetyNet,
    credentialPublicKey: isoBase64URL.toBuffer(credentialPublicKey),
    x5c,
  });

  expect(verified).toEqual(true);
});

test('should verify attestation with rsa_emsa_pkcs1_sha256_raw authenticator algorithm in metadata', async () => {
  const metadataStatement: MetadataStatement = {
    legalHeader: 'https://fidoalliance.org/metadata/metadata-statement-legal-header/',
    aaguid: '08987058-cadc-4b81-b6e1-30de50dcbe96',
    description: 'Windows Hello Hardware Authenticator',
    authenticatorVersion: 1,
    protocolFamily: 'fido2',
    schema: 3,
    upv: [{ major: 1, minor: 0 }],
    authenticationAlgorithms: ['rsassa_pkcsv15_sha256_raw'],
    publicKeyAlgAndEncodings: ['cose'],
    attestationTypes: ['attca'],
    userVerificationDetails: [
      [{ userVerificationMethod: 'eyeprint_internal' }],
      [{ userVerificationMethod: 'passcode_internal' }],
      [{ userVerificationMethod: 'fingerprint_internal' }],
      [{ userVerificationMethod: 'faceprint_internal' }],
    ],
    keyProtection: ['hardware'],
    isKeyRestricted: false,
    matcherProtection: ['software'],
    attachmentHint: ['internal'],
    tcDisplay: [],
    attestationRootCertificates: [
      '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',
    ],
    icon: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAYAAABV7bNHAAACkUlEQVR42uyai3GDMAyGQyegGzACnaCMkBHoBhkhnSAj0A2SDaAT0E6QbEA3cOXW6XEpBtnImMv9utOllxjF/qKHLTdRSm0gdnkAAgACIAACIAACIAACIAgAARAAARAAARAAARBEAFCSJINKkpLuSTtSZbQz76W25zhKkpFWPbtaz6Q75vPuoluuPmqxlZK2yi76s9RznjlpN2K7CrFWaUAHNS0HT0Atw3YpDSjxbdoPuaziG3uk579cvIdeWsbQD7L7NAYoWpKmLy8chueO5reB7KKKrQnQJdDYn9AJZHc5QBT7enINY2hjxrqItsvJWSdxFxKuYlOlWJmE6zPPcsJuN7WFiF7me5DOAws4OyZyG6TOsr/KQziDaJm/mcy2V1V0+T0JeXxqqlrWC9mGGy3O6wwFaI0SdR+EMg9AEAACIAByqViZb+/prgFdN6qb306j3lTWs0BJ76Qjw0ktO+3ad60PQhMrfM9YwqK7lUPe4j+/OR40cDaqJeJ+xo80JsWih1WTBAcb8ysKrb+TfowQKy3v55wbBkk49FJbQusqr4snadL9hEtXC3nO1G1HG6UfxIj5oDnJlHPOVVAerWGmvYQxwc70hiTh7Bidy3/3ZFE6isxf8epNhUCl4n5ftYqWKzMP3IIquaFnquXO0sZ1yn/RWq69SuK6GdPXORfSz4HPnk1bNXO0+UZze5HqKIodNYwnHVVcOUivNcStxj4CGFYhWAWgXgmuF4JzdMhn6wDUm1DpmFyVY7IvQqeTRdod2v2F8lNn/gcpW+rUsOi9mAmFwlSo3Pw9JQ3p+8bhgnAMkPM613BxOBQqc2FEB4SmPQSAAAiAAAiAAAiAAAiAIAAEQAAEQAAEQPco3wIMADOXgFhOTghuAAAAAElFTkSuQmCC',
    authenticatorGetInfo: {
      versions: ['FIDO_2_0'],
      aaguid: '08987058cadc4b81b6e130de50dcbe96',
      options: { plat: true, rk: true, up: true },
    },
  };

  // Extracted from an actual TPM|ECC response
  const x5c = [
    'MIIFuTCCA6GgAwIBAgIQAM86nt2LQk-si1Q75opOtjANBgkqhkiG9w0BAQsFADBCMUAwPgYDVQQDEzdOQ1UtSU5UQy1LRVlJRC0xN0EwMDU3NUQwNUU1OEUzODgxMjEwQkI5OEIxMDQ1QkI0QzMwNjM5MB4XDTIxMTIwMTA3MTMwOFoXDTI3MDYwMzE3NTExOFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN42zmd-TJwY8b8KKakCP_Jmq46s9qIcae5EObWRtWqw-qXBM9fH15vJ3UrE1mHv9mjCsV384_TJP7snP7MHy93jQOZNvR-T8JGNXR1Zhzg1MOjsZlv69w-shGZBF3lWXKKrdyS4q5KP8WbC6A30LVM_Ic0uAxkOeS-z4CdwWC4au2i8TkCTsUSenc98SFEksNOQONdNLA5qQInYCWppdT2lzEi-BbTV2GyropPgL3PCHGKVNt73XWzWZD_e9zuPNrOG9gfhh1hJaQS82TIul59Qp4C6AbIzH5uvhSh3_mhK2YU7Je6-FE_cvFLiTLt4vVimxd5uNGO4Oth_nfUm_sECAwEAAaOCAeswggHnMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMRYwFAYFZ4EFAgEMC2lkOjQ5NEU1NDQzMQ4wDAYFZ4EFAgIMA0NOTDEWMBQGBWeBBQIDDAtpZDowMDAyMDAwMDAfBgNVHSMEGDAWgBTg0USwFsuPP50VHiH8i_DHd-1qLjAdBgNVHQ4EFgQU99bEZ0-Oi7GG2f-i68p7Xf1-diQwgbMGCCsGAQUFBwEBBIGmMIGjMIGgBggrBgEFBQcwAoaBk2h0dHA6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1pbnRjLWtleWlkLTE3YTAwNTc1ZDA1ZTU4ZTM4ODEyMTBiYjk4YjEwNDViYjRjMzA2MzkvYTdjNjk5MjUtZjM4Yi00ZmQwLWExZWMtMmYzMjI1MjA1YmM4LmNlcjANBgkqhkiG9w0BAQsFAAOCAgEAMwXq91wHH27AiR6rrWH3L7xEJ6o-wnoP808WisQcQ5gCUh4o0E3eeICh1IjPpr-n5CCMwU8GSzX5vQGF3VKa8FoEBNrhT4IuD-3qNv939NW1k4VPVQGTwgXy8YHiAlGnLmAIiqmEAgsn9fKLzBDhT448CJWyWzmtA5TflBX_jeL5V94hTvOMDtdtPQOpdGKlpYyArz3_sU8_XyOZad3DAbQbKOiFfzJoyr4CUDjZy1wHcO5ouwW33syPyrQwlqgnS8whBYXPK2M9Y-qT2--VutBAZIWI2wdiqMhY-RTm9OIbURZWmqVZ2DPn7dEGMow9TgdNYHL9m3CYsvRQejWyBffU0l8aLRzt330FqjHIK1x8kvk25V-mF10bTIejS6F516k3iZ2FbH5UeiZVE9ofVgN_lJ8KwyeOUjyG66VuH6dmnRfn4gg_2Uyj9TrDF0dJpoCKTspShuIaPD2-H-pkDQlDkldXo-bHlrGXJJGRBbhutxbBxozRsvkYhgoR4TbSzyDcFzFnDJd1ib_Z9C9q5KwaUiREX0b1rLCd1BZ-JXYGiQTrfnMZDvbHSXuZ-HXhcF9t5TZ8f4xDZX4gfsyj75uGJ34e4ThWxnNvdY7HkhFSXJzmvT6dIlIW1UorbYYm-UtbW4e8GwEVXquG0bpmWIXmL2k9D_WCSkyzkR7tPvw',
    'MIIG7DCCBNSgAwIBAgITMwAAA-Y6aLPA71ZHOwAAAAAD5jANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE2MDQGA1UEAxMtTWljcm9zb2Z0IFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE0MB4XDTIxMDYwMzE3NTExOFoXDTI3MDYwMzE3NTExOFowQjFAMD4GA1UEAxM3TkNVLUlOVEMtS0VZSUQtMTdBMDA1NzVEMDVFNThFMzg4MTIxMEJCOThCMTA0NUJCNEMzMDYzOTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAO26HxYkAnL4SBpcIIDBFYw95P18eBVzl0owJPKtEwqtJhRArv6DQMDGKPw9HGy3Vtmh5VvrGgKh6LPyTbqN2xITi-wgPUIv7Mn-WtvzPO70dnhdRvw1vDY8LeulOh2l9zU2o2jII0HzLTl_LJqKmrN3yZpq1NneSQ49l3sbXvsW0eKSj2iCtgvOk2FhY-Os3cyexx6phX5I26BmoP-Y-W5kYqtNw2o8rxol_I0v51PVzNcLBwseGOpHNYtRF0m0QdoudCKZKk0hWzKPA4BE35wSSWGjgUbp91Pjzva33tYmOlk0UOLoIT2rZ2Y5feG3QpBuacD1ImDEUQ01-kJ1S2bATRR3BoaJtRbOCRoz41MS-2XfbXhcnzZxbT5TY7dlbX4oKYZn2Wqw-TYmfBiPYBX-Mo6wObruVOs6Lk04XzznXvx5lLKLNdvDBJxG3dZIzgepo9fLrp7hTiKw0T1EdYn6-MjUO7utoq7RmKA_AzFI1VLTfVJxPn_RahYPJmt8a8F2X7WlYPg5vayPDyWtmXtuuoxoAclNp3ViC9ko5LVr7M78C2RA1T94yk2eAEm_ueCuqn8mrmqQjFo3fMAfvRB2nL66tQhBZwmWyRIjuycRCJRdtSrwjSXRywA_VHLajhVutGzPrizmFcygT3ozL1NB6s5Ill5o4DpQsE9qNIOHAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBTg0USwFsuPP50VHiH8i_DHd-1qLjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAGW4yKQ4HaO4JdNMVjVO4mCM0lbLMmXQ0YJtyDHCIE6hsywTYv30DeUDm7Nmmhap9nWp26mSihb7qKQuyhdZkfhA10sp4wDbNpcXjQjdEaE2T1rcgKfounCPQRSW1V42DUgX_Bzuh0flbLYGOJIvugR46gBMUuKVQWmMQKyOMwmofFI8xG_z3VaLMcsgQ8Fl0cvJ6XZ2Jly-QRbZ2v44KNItTTuQKYJCL4kx2b50I4CkrRBaq2LAB-npikLN6xxHqsPvulA0t2WRfF9QzzDZhkVVZ5iCP1fAu5dnHvq0ArBlY2W29OIH_zviW2av88wxZ7FSQzIHu6B8GL45s6skvPa7E9lU6hG186LjrJtHJd0Qad3KYzZQyLKT78m1YiZXLFM02vsctM7nXqtndDjbDPVCota3mg8Jgi2s7-Aq59TL9ZBnRMEvJ5m1Rze1ofFwfO21ktBtLB8vXhzkHjtXy5ld0UQXmdbcs32uaqx6Q3_jVzXlXNNjuG6YBW9iBNL2ar3MtFt66LogL1gmOkyrjGK2Cdyzy1lEupr_SKtggthTyubemmf9G6hJtUZuT_gdFxVZm-MOvCtdNsqdi4HaU8VTCPB999upaEc5vv5KeEQ2xQk0wNmffMlGXGHJrQw8WBwCKkm3TW8hjnhZ9e6ePQvdMEzPhefsxjiQirzpf6lB',
  ];
  const credentialPublicKey =
    'pAEDAzkBACBZAQC3X5SKwYUkxFxxyvCnz_37Z57eSdsgQuiBLDaBOd1R6VEZReAV3nVr_7jiRgmWfu1C-S3Aro65eSG5shcDCgIvY3KdEI8K5ENEPlmucjnFILBAE_MZtPmZlkEDmVCDcVspHX2iKqiVWYV6IFzVX1QUf0SAlWijV9NEfKDbij34ddV0qfG2nEMA0_xVpN2OK2BVXonFg6tS3T00XlFh4MdzIauIHTDT63eAdHlkFrMqU53T5IqDvL3VurBmBjYRJ3VDT9mA2sm7fSrJNXhSVLPst-ZsiOioVKrpzFE9sJmyCQvq2nGZ2RhDo8FfAKiw0kvJRkCSSe1ddxryk9_VSCprIUMBAAE';

  const verified = await verifyAttestationWithMetadata({
    statement: metadataStatement,
    credentialPublicKey: isoBase64URL.toBuffer(credentialPublicKey),
    x5c,
  });

  expect(verified).toEqual(true);
});

test('should not validate certificate path when authenticator is self-referencing its attestation statement certificates', async () => {
  const metadataStatement: MetadataStatement = {
    legalHeader: 'https://fidoalliance.org/metadata/metadata-statement-legal-header/',
    description:
      'Virtual Secp256R1 FIDO2 Conformance Testing CTAP2 Authenticator with Self Batch Referencing',
    aaguid: '5b65dac1-7af4-46e6-8a4f-8701fcc4f3b4',
    alternativeDescriptions: {
      'ru-RU':
        'Виртуальный Secp256R1 CTAP2 аутентификатор для тестирование серверов на соответсвие спецификации FIDO2 с одинаковыми сертификатами',
    },
    protocolFamily: 'fido2',
    authenticatorVersion: 2,
    upv: [{ major: 1, minor: 0 }],
    authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
    publicKeyAlgAndEncodings: ['cose'],
    attestationTypes: ['basic_full'],
    schema: 3,
    userVerificationDetails: [
      [{ userVerificationMethod: 'none' }],
      [{ userVerificationMethod: 'presence_internal' }],
      [{ userVerificationMethod: 'passcode_external', caDesc: { base: 10, minLength: 4 } }],
      [
        { userVerificationMethod: 'passcode_external', caDesc: { base: 10, minLength: 4 } },
        { userVerificationMethod: 'presence_internal' },
      ],
    ],
    keyProtection: ['hardware', 'secure_element'],
    matcherProtection: ['on_chip'],
    cryptoStrength: 128,
    attachmentHint: ['external', 'wired', 'wireless', 'nfc'],
    tcDisplay: [],
    attestationRootCertificates: [
      'MIIEQTCCAimgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzk0M1oXDTI4MDUyMDE0Mzk0M1owgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB+8rpf232RJlnYse+9yAEAqdsbyMPZVbxeqmZtZf8S/UIqvjp7wzQE/Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi/QF5MA0GCSqGSIb3DQEBCwUAA4ICAQCH3aCf+CCJBdEtQc4JpOnUelwGGw7DxnBMokHHBgrzJxDn9BFcFwxGLxrFV7EfYehQNOD+74OS8fZRgZiNf9EDGAYiHh0+CspfBWd20zCIjlCdDBcyhwq3PLJ65JC/og3CT9AK4kvks4DI+01RYxNv9S8Jx1haO1lgU55hBIr1P/p21ZKnpcCEhPjB/cIFrHJqL5iJGfed+LXni9Suq24OHnp44Mrv4h7OD2elu5yWfdfFb+RGG2TYURFIGYGijsii093w0ZMBOfBS+3Xq/DrHeZbZrrNkY455gJCZ5eV83Nrt9J9/UF0VZHl/hwnSAUC/b3tN/l0ZlC9kPcNzJD04l4ndFBD2KdfQ2HGTX7pybWLZ7yH2BM3ui2OpiacaOzd7OE91rHYB2uZyQ7jdg25yF9M8QI9NHM/itCjdBvAYt4QCT8dX6gmZiIGR2F/YXZAsybtJ16pnUmODVbW80lPbzy+PUQYX79opeD9u6MBorzr9g08Elpb1F3DgSd8VSLlsR2QPllKl4AcJDMIOfZHOQGOzatMV7ipEVRa0L5FnjAWpHHvSNcsjD4Cul562mO3MlI2pCyo+US+nIzG5XZmOeu4Db/Kw/dEPOo2ztHwlU0qKJ7REBsbt63jdQtlwLuiLHwkpiwnrAOZfwbLLu9Yz4tL1eJlQffuwS/Aolsz7HA==',
    ],
    supportedExtensions: [
      { id: 'hmac-secret', fail_if_unknown: false },
      { id: 'credProtect', fail_if_unknown: false },
    ],
    authenticatorGetInfo: {
      versions: ['U2F_V2', 'FIDO_2_0'],
      extensions: ['credProtect', 'hmac-secret'],
      aaguid: '5b65dac17af446e68a4f8701fcc4f3b4',
      options: { plat: false, rk: true, clientPin: true, up: true, uv: true },
      maxMsgSize: 1200,
    },
  };

  const x5c = [
    'MIIEQTCCAimgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzk0M1oXDTI4MDUyMDE0Mzk0M1owgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBCwUAA4ICAQCH3aCf-CCJBdEtQc4JpOnUelwGGw7DxnBMokHHBgrzJxDn9BFcFwxGLxrFV7EfYehQNOD-74OS8fZRgZiNf9EDGAYiHh0-CspfBWd20zCIjlCdDBcyhwq3PLJ65JC_og3CT9AK4kvks4DI-01RYxNv9S8Jx1haO1lgU55hBIr1P_p21ZKnpcCEhPjB_cIFrHJqL5iJGfed-LXni9Suq24OHnp44Mrv4h7OD2elu5yWfdfFb-RGG2TYURFIGYGijsii093w0ZMBOfBS-3Xq_DrHeZbZrrNkY455gJCZ5eV83Nrt9J9_UF0VZHl_hwnSAUC_b3tN_l0ZlC9kPcNzJD04l4ndFBD2KdfQ2HGTX7pybWLZ7yH2BM3ui2OpiacaOzd7OE91rHYB2uZyQ7jdg25yF9M8QI9NHM_itCjdBvAYt4QCT8dX6gmZiIGR2F_YXZAsybtJ16pnUmODVbW80lPbzy-PUQYX79opeD9u6MBorzr9g08Elpb1F3DgSd8VSLlsR2QPllKl4AcJDMIOfZHOQGOzatMV7ipEVRa0L5FnjAWpHHvSNcsjD4Cul562mO3MlI2pCyo-US-nIzG5XZmOeu4Db_Kw_dEPOo2ztHwlU0qKJ7REBsbt63jdQtlwLuiLHwkpiwnrAOZfwbLLu9Yz4tL1eJlQffuwS_Aolsz7HA',
  ];
  const credentialPublicKey =
    'pQECAyYgASFYIBdmUVOxrn-OOtkVwGP_vAspH3VkgzcGXVlu3-acb7EZIlggKgDTs0fr2d51sLR6uL3KP2cqR3iIUkKMCjyMJhYOkf4';

  const verified = await verifyAttestationWithMetadata({
    statement: metadataStatement,
    credentialPublicKey: isoBase64URL.toBuffer(credentialPublicKey),
    x5c,
  });

  expect(verified).toEqual(true);
});

test('should verify idmelon attestation with updated root certificate', async () => {
  /**
   * See https://github.com/MasterKale/SimpleWebAuthn/issues/302 for more context, basically
   * IDmelon's root cert in FIDO MDS was missing an extension. I worked with IDmelon to generate a
   * new root certificate, which is included below and will eventually get rolled out via FIDO MDS.
   */
  const metadataStatement: MetadataStatement = {
    legalHeader:
      'Submission of this statement and retrieval and use of this statement indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/.',
    aaguid: '820d89ed-d65a-409e-85cb-f73f0578f82a',
    description: 'Vancosys iOS Authenticator',
    authenticatorVersion: 2,
    protocolFamily: 'fido2',
    schema: 3,
    upv: [{ major: 1, minor: 0 }],
    authenticationAlgorithms: ['secp256r1_ecdsa_sha256_raw'],
    publicKeyAlgAndEncodings: ['cose'],
    attestationTypes: ['basic_full'],
    userVerificationDetails: [
      [
        { userVerificationMethod: 'faceprint_internal' },
        { userVerificationMethod: 'voiceprint_internal' },
        { userVerificationMethod: 'passcode_internal' },
        { userVerificationMethod: 'eyeprint_internal' },
        { userVerificationMethod: 'handprint_internal' },
        { userVerificationMethod: 'fingerprint_internal' },
        { userVerificationMethod: 'pattern_internal' },
        { userVerificationMethod: 'location_internal' },
        { userVerificationMethod: 'presence_internal' },
      ],
    ],
    keyProtection: ['hardware', 'secure_element'],
    matcherProtection: ['on_chip'],
    cryptoStrength: 128,
    attachmentHint: ['external'],
    tcDisplay: [],
    attestationRootCertificates: [
      'MIIByzCCAXGgAwIBAgIJANmMNK6jVpuuMAoGCCqGSM49BAMCMEExJDAiBgNVBAoMG1ZhbmNvc3lzIERhdGEgU2VjdXJpdHkgSW5jLjEZMBcGA1UEAwwQVmFuY29zeXMgUm9vdCBDQTAgFw0yMjEyMTQxODQxMDlaGA8yMDcyMTIwMTE4NDEwOVowQTEkMCIGA1UECgwbVmFuY29zeXMgRGF0YSBTZWN1cml0eSBJbmMuMRkwFwYDVQQDDBBWYW5jb3N5cyBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEalYgEopnKScAm+d9f1XpGB3zbkZCD3hZEKuxTclpBYlj4ypNRg0gMSa7geBgd6nck50YaVhdy75uIc2wbWX8t6NQME4wHQYDVR0OBBYEFOxyf0cDs8Yl+VnWSZ1uYJAKkFeVMB8GA1UdIwQYMBaAFOxyf0cDs8Yl+VnWSZ1uYJAKkFeVMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAO2XuiRDXxy/UkWhsuZQYNUXeOj08AeTWADAqXvcA30hAiBi2cdGd61PNwHDTYjXPenPcD8S0rFTDncNWfs3E/WDXA==',
    ],
    icon: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAM1BMVEUtmc3y+fyWzOZis9rK5fI6n9B8v+Cw2ezl8vlHptNVrNbX7Paj0ulvud293++JxuP///89HRvpAAAAEXRSTlP/////////////////////ACWtmWIAAABsSURBVHgBxdPBCoAwDIPh/yDise//tIIQCZo6RNGdtuWDstFSg/UOgMiADQBJ6J4iCwS4BgzBuEQHCoFa+mdM+qijsDMVhBfdoRFaAL4nAe6AeghODYPnsaNyLuAqg5AHwO9AYu5BmqEPhncFmecvM5KKQHMAAAAASUVORK5CYII=',
    authenticatorGetInfo: {
      versions: ['FIDO_2_0'],
      extensions: ['hmac-secret'],
      aaguid: '820d89edd65a409e85cbf73f0578f82a',
      options: { plat: false, rk: true, up: true, uv: true },
      maxMsgSize: 2048,
    },
  };

  const x5c = [
    'MIIB6TCCAY+gAwIBAgIJAJz56pzvu76hMAoGCCqGSM49BAMCMEExJDAiBgNVBAoMG1ZhbmNvc3lzIERhdGEgU2VjdXJpdHkgSW5jLjEZMBcGA1UEAwwQVmFuY29zeXMgUm9vdCBDQTAgFw0xODEyMjIxNzQzMjhaGA8yMDY4MTIwOTE3NDMyOFowfDELMAkGA1UEBhMCQ0ExJDAiBgNVBAoMG1ZhbmNvc3lzIERhdGEgU2VjdXJpdHkgSW5jLjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEjMCEGA1UEAwwaVmFuY29zeXMgaU9TIEF1dGhlbnRpY2F0b3IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATZVzbtmSJbzsoN6mfdD+t1LV52zB+LWN0UusmV9+sRmfNB49adqPQ+h0JOlEwfL4zkbMmuDr6JhBRKJ5/c0SkeozMwMTAMBgNVHRMBAf8EAjAAMCEGCysGAQQBguUcAQEEBBIEEIINie3WWkCehcv3PwV4+CowCgYIKoZIzj0EAwIDSAAwRQIgV7++U2fQyy6Qido7fDhsi5Grrt76LTgZ5XJlA9UKEVECIQDJO0YHevdU77VlZ+Of58oKMjWD3SkzC1SWSlhl3nezHQ==',
  ];
  const credentialPublicKey =
    'pQECAyYgASFYINuJbeLdkZwgKtUw2VSopICTTO5PKdj95GXJ7JCsQi7iIlggxygEp0_P0oMXhfw2BjtL0M7-yIpnk5uSHc0oNkXfdJw';

  const verified = await verifyAttestationWithMetadata({
    statement: metadataStatement,
    credentialPublicKey: isoBase64URL.toBuffer(credentialPublicKey),
    x5c,
  });

  expect(verified).toEqual(true);
});
