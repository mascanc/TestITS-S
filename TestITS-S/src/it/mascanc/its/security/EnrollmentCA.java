package it.mascanc.its.security;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.InternalErrorException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

/**
 * They are defined in section 7.2.4, Subordinate certification authority
 * certificates.
 * 
 * <h1>CA Certificate Request</h1> In 102 941 the certificate request for the CA
 * shall be sent by an off-band mechanism (section 6.2.1). The trust is defined
 * by the EU commission document
 * 
 * @author max
 *
 */
public class EnrollmentCA implements Runnable {
	public static final int port = 8887;

	// This is the hashmap of the sending its. The Enrolment CA already knows the
	// ITS, and it shall know the permissions,
	// and the validity period and region.
	public static final HashMap<String, EtsiTs103097Certificate> SITS = new HashMap<String, EtsiTs103097Certificate>();

	// This is the list of enrolled SITS
	public static final HashMap<String, EtsiTs103097Certificate> ENROLLED_SITS = new HashMap<String, EtsiTs103097Certificate>();
	// Crypto stuff that I need.
	private EtsiTs103097Certificate myCertificate;

	private KeyPair signingKeys;

	private KeyPair encryptionKeys;

	private EtsiTs103097Certificate[] enrolmentCaChain;

	//private EtsiTs103097Certificate rootCaCert;

	private ETSITS102941MessagesCaGenerator messagesCaGenerator;

	private DefaultCryptoManager cryptoManager;

	public EtsiTs103097Certificate getCertificate() {
		return this.myCertificate;
	}

	public EnrollmentCA() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {

		// Create a crypto manager in charge of communicating with underlying
		// cryptographic components
		cryptoManager = new DefaultCryptoManager();
		// Initialize the crypto manager to use soft keys using the bouncy castle
		// cryptographic provider.
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

		// Create a ETSITS102941MessagesCaGenerator generator
		messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION, cryptoManager, // The
																													// initialized
																													// crypto
																													// manager
																													// to
																													// use.
				HashAlgorithm.sha256, // digest algorithm to use.
				Signature.SignatureChoices.ecdsaNistP256Signature, // define which signature scheme to use.
				false); // If EC points should be represented as uncompressed.

	}

	@Override
	public void run() {
		System.out.println("Enrolment CA Server starting");
		try (ServerSocket mySocket = new ServerSocket(port)) {
			System.out.println("Waiting Enrollment CA on port " + port);
			Socket clientSocket = mySocket.accept();
			System.out.println("Obtained client connection from: " + clientSocket.getInetAddress());

		} catch (Throwable e) {
			throw new IllegalStateException(e);

		}

	}

	public void setCertificate(EtsiTs103097Certificate cert) {
		System.out.println("Enrolment CA: reading certificate " + cert);
		this.myCertificate = cert;

	}

	public void setSigningKeys(KeyPair keys) {
		System.out.println("Enrolment CA: reading keys " + keys);
		this.signingKeys = keys;

	}

	/**
	 * This method stores the Sendint ITS-S id.
	 * 
	 * @param sits_ca_and_id
	 */
	public void setSitsId(CAandID sits_ca_and_id) {
		System.out.println("Received initializion data for ITS-S " + sits_ca_and_id.getMyID());
		SITS.put(sits_ca_and_id.getMyID(), sits_ca_and_id.getPublicKey());

	}

	/**
	 * This method enrols a ITS station
	 * 
	 * @param enrolmentMSgToSendToEnrolmentCA
	 * @return the byte[] encoded  enrolment response.
	 * @throws IOException
	 * @throws IllegalArgumentException
	 * @throws GeneralSecurityException
	 * @throws InternalErrorException
	 * @throws DecryptionFailedException
	 * @throws SignatureVerificationException
	 * @throws MessageParsingException
	 */
	public byte[] enrollITS(byte[] enrolmentMSgToSendToEnrolmentCA)
			throws IllegalArgumentException, IOException, GeneralSecurityException, MessageParsingException,
			SignatureVerificationException, DecryptionFailedException, InternalErrorException {

		// Msg is an encrypted data.
		EtsiTs103097DataEncryptedUnicast msg = new EtsiTs103097DataEncryptedUnicast(enrolmentMSgToSendToEnrolmentCA);

		// First build a certificate store and a trust store to verify signature.
		// These can be null if only initial messages are used.
		// EtsiTs103097Certificate[] enrollmentCredCertChain = new
		// EtsiTs103097Certificate[]{enrolmentCredCert, enrolmentCACert,rootCACert};
		// Map<HashedId8, Certificate> enrolCredCertStore =
		// messagesCaGenerator.buildCertStore(enrollmentCredCertChain);
//		Map<HashedId8, Certificate> trustStore = messagesCaGenerator
//				.buildCertStore(new EtsiTs103097Certificate[] { rootCaCert });

		// Then create a receiver store to decrypt the message
		Map<HashedId8, Receiver> enrolCAReceipients = messagesCaGenerator.buildRecieverStore(
				new Receiver[] { new CertificateReciever(encryptionKeys.getPrivate(), myCertificate) });

		// Now try to decrypt:
		RequestVerifyResult<InnerEcRequest> enrolmentRequestResult = messagesCaGenerator
				.decryptAndVerifyEnrolmentRequestMessage(msg, null, null, enrolCAReceipients);
		System.out
				.println("Received a enrolment request message from: " + enrolmentRequestResult.getSignerIdentifier()); // The
																														// identifier
																														// of
																														// the
																														// signer
		System.out.println("Header info " + enrolmentRequestResult.getHeaderInfo()); // The header information of the
																						// signer of the message
		System.out.println("The inner message " + enrolmentRequestResult.getValue()); // The inner message that was
																						// signed and or encrypted.
	//	SecretKey key = enrolmentRequestResult.getSecretKey(); // The symmetrical key used in Ecies request operations
																// and is set when
		// verifying all
		InnerEcRequest msgRequest = enrolmentRequestResult.getValue();
		byte[] itsId = msgRequest.getItsId();

		System.out.println("The ITS id received is " + new String(itsId));
		// let me get the information for this ITS ID

		InnerEcResponse innerEcResponse = null;

		if (SITS.containsKey(new String(itsId))) {
			System.out.println("The S-ITS-S is known, generating its certificate");

			ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(
					cryptoManager);
			KeyPair enrollmentCredentialSigningKeys = cryptoManager
					.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
			KeyPair enrollmentCredentialEncryptionKeys = cryptoManager
					.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
			ValidityPeriod enrollCertValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 35);

			List<Integer> countries = new ArrayList<Integer>();
			countries.add(Constants.REGION);
			GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);

			
			EtsiTs103097Certificate enrollmentCredential = enrollmentCredentialCertGenerator.genEnrollCredential(
					UUID.randomUUID().toString(), // THIS IS A UNIQUE ID FOR THE CERTIFICATE THAT IT WILL BE USED BY THE AA TO CHECK IF THIS CERT IS VALID (section 6.2.3.3.1)
					enrollCertValidityPeriod, region, Hex.decode("01C0"), // SSP data set in
																			// SecuredCertificateRequestService
																			// appPermission, two byte, for example:
																			// 0x01C0
					1, // assuranceLevel
					3, // confidenceLevel
					SignatureChoices.ecdsaNistP256Signature, // signingPublicKeyAlgorithm
					enrollmentCredentialSigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
					myCertificate, // signerCertificate
					signingKeys.getPublic(), // signCertificatePublicKey,
					signingKeys.getPrivate(), SymmAlgorithm.aes128Ccm, // symmAlgorithm
					BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
					enrollmentCredentialEncryptionKeys.getPublic() // encryption public key
			);
			innerEcResponse = new InnerEcResponse(enrolmentRequestResult.getRequestHash(), EnrollmentResponseCode.ok,
					enrollmentCredential);
		} else {
			System.out.println("Ths S-ITS-S is UNKNOWN");
			innerEcResponse = new InnerEcResponse(enrolmentRequestResult.getRequestHash(),
					EnrollmentResponseCode.unknownits, null);

		}

		EtsiTs103097DataEncryptedUnicast enrolResponseMessage = messagesCaGenerator.genEnrolmentResponseMessage(
				new Time64(new Date()), // generation Time
				innerEcResponse, enrolmentCaChain, // Chain of EA used to sign message
				signingKeys.getPrivate(), SymmAlgorithm.aes128Ccm, // Encryption algorithm used
				enrolmentRequestResult.getSecretKey()); // Use symmetric key from the verification result when verifying
														// the request.

		return enrolResponseMessage.getEncoded();
	}

	public KeyPair getEncryptionKeys() {
		return this.encryptionKeys;
	}

	public void setEncrptionKeys(KeyPair enrollmentCAEncryptionKeys) {
		this.encryptionKeys = enrollmentCAEncryptionKeys;

	}

	public void setEnrolmentCAChain(EtsiTs103097Certificate[] enrollmentCAChain) {
		this.enrolmentCaChain = enrollmentCAChain;

	}

}
