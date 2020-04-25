package it.mascanc.its.security;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException;
import org.certificateservices.custom.c2x.etsits102941.v131.InternalErrorException;
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException;
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.CertificateRecipient;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.Recipient;

/**
 * This is the sending ITS.
 * 
 * As part of the manufacturing, the following information associated with the
 * identity of the station shall be established within the ITS-S and the EA.
 * (ETSI TS 102 941 v1.3.1, section 6.1.2)
 * 
 * <ol>
 * <li>A canonical identifier (which guarantees uniqueness), not specified</li>
 * <li>Public key certificate and network address for EA and AA</li>
 * <li>The set of current known trusted AA used to trust communication</li>
 * <li>Canonical key pair</li>
 * <li>The trust anchor public key cert</li>
 * <li>In case of multiple root CA, the TLM publick key cert and the CPOC
 * network address</li>
 * </ol>
 * 
 * The EA shall know
 * <ol>
 * <li>The permanent canonical identifier of the station</li>
 * <li>The profile information for the ITS-S that may contain an initial list of
 * maximum appPremissions (ITS-AID with SSP) region restrictions and assurance
 * level, which may be modified</li>
 * <li>The public ckey from the key pair belonging to the ITS-S</li>
 * </ol>
 * 
 * <h1>Maintenance of an ITS-S</h1> If an EA or AA is added or removed by the
 * system, the Root CA shall inform the enrolled ITS-S. (so the root ca shall be
 * aware of the enrolled ITS-S). If there are multiple CA, then it's a TL duty
 * with the CTL/CRL messages. (section 6.1.5)
 * 
 * 
 * @author max
 *
 */
public class SendingITS {

	/** This is my canonical identifier. */
	private static final String myID = UUID.randomUUID().toString();
	private DefaultCryptoManager cryptoManager;

	// my crypto stuff.
	// Those are keys to request the enrlomentCert
	private KeyPair enrolmentCredentialSignKeys;
	private KeyPair enrolmentCredentialEncryptionKeys;
	private KeyPair enrolmentCredentialReSignKeys;

	// Those are keys for the authTicket
	private KeyPair authTicketSignKeys;
	private KeyPair authTicketEncryptionKeys;

	private EtsiTs103097Certificate rootCACert;
	private EtsiTs103097Certificate enrolmentCaCert;
	private EtsiTs103097Certificate authorizationCaCert;

	private EtsiTs103097Certificate[] enrolmentCredChain;
	private EtsiTs103097Certificate enrolmentCredCert;

	SecureRandom secureRandom = new SecureRandom();

	// Generator for the request
	private ETSITS102941MessagesCaGenerator messagesCaGenerator;
	private GeographicRegion region;
	private PublicVerificationKeyChoices signAlg;
	private EncryptResult initialEnrolRequestMessageResult;
	private BasePublicEncryptionKeyChoices encAlg;
	private Date timeStamp;
	private SharedAtRequest sharedAtRequest;
	private SecretKey mySecretKey;
	private InnerAtResponse ticket;

	/**
	 * Constructor: it shall follow the initialization phase
	 * 
	 * @throws BadCredentialsException
	 * @throws IOException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalArgumentException
	 * @throws ParseException
	 */
	public SendingITS() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException, ParseException {
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
		signAlg = ecdsaNistP256;
		encAlg = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;

		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION);
		region = GeographicRegion.generateRegionForCountrys(countries);

		enrolmentCredentialSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
		enrolmentCredentialReSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
		enrolmentCredentialEncryptionKeys = cryptoManager.generateKeyPair(ecdsaNistP256);

		authTicketSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
		authTicketEncryptionKeys = cryptoManager.generateKeyPair(ecdsaNistP256);

	}

	public void setAuthorizationTicket(byte[] authorizationResponse)
			throws IllegalArgumentException, IOException, GeneralSecurityException, MessageParsingException,
			SignatureVerificationException, DecryptionFailedException, InternalErrorException {
		EtsiTs103097DataEncryptedUnicast msg = new EtsiTs103097DataEncryptedUnicast(authorizationResponse);

		Map<HashedId8, Certificate> trustStore = messagesCaGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { rootCACert });

		Map<HashedId8, Receiver> authTicketSharedKeyReceivers = messagesCaGenerator
				.buildRecieverStore(new Receiver[] { new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, mySecretKey) });
		Map<HashedId8, Certificate> authCACertStore = messagesCaGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { authorizationCaCert, rootCACert });
		VerifyResult<InnerAtResponse> authResponseResult = messagesCaGenerator
				.decryptAndVerifyAuthorizationResponseMessage(msg, authCACertStore, // certificate store
																					// containing
																					// certificates for
																					// auth cert.
						trustStore, authTicketSharedKeyReceivers);
		ticket = authResponseResult.getValue();
		System.out.println("Finally I have an authorization Ticket!!! "+ authResponseResult);
	}

	private byte[] genHmacKey() {
		byte[] hmacKey = new byte[32];
		secureRandom.nextBytes(hmacKey);
		return hmacKey;
	}

	private byte[] genKeyTag(byte[] hmacKey, PublicVerificationKey verificationKey, PublicEncryptionKey encryptionKey)
			throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream daos = new DataOutputStream(baos);
		daos.write(hmacKey);
		verificationKey.encode(daos);
		if (encryptionKey != null) {
			encryptionKey.encode(daos);
		}
		daos.close();
		byte[] data = baos.toByteArray();
		Digest digest = new SHA256Digest();
		HMac hMac = new HMac(digest);
		hMac.update(data, 0, data.length);

		byte[] macData = new byte[hMac.getMacSize()];
		hMac.doFinal(data, 0);

		return Arrays.copyOf(macData, 16);
	}

	private SharedAtRequest genDummySharedAtRequest(PublicKeys publicKeys, byte[] hmacKey) throws Exception {
		HashedId8 eaId = new HashedId8(cryptoManager.digest(enrolmentCaCert.getEncoded(), HashAlgorithm.sha256));
		byte[] keyTag = genKeyTag(hmacKey, publicKeys.getVerificationKey(), publicKeys.getEncryptionKey());
		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(
				ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
		PsidSsp[] appPermissions = new PsidSsp[] { appPermCertMan };

		CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes(
				myID + ".autostrade.it", new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 25), region,
				new SubjectAssurance(1, 3), appPermissions, null);

		return new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131, certificateSubjectAttributes);
	}

	/**
	 * Given an enrolment credential, it shall check for authorization. When the
	 * authorization is received, the ITS-S has a set of authorization tickets to
	 * allow signed transmission of messages to any other ITS-S that do not reveal
	 * the canonical identity nor the enrolment credntial of the transmitting ITS-S
	 * 
	 * @param service
	 * @return
	 * @throws Exception
	 */
	public byte[] requestAuthorizationFor(String service) throws Exception {
		PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, authTicketSignKeys.getPublic(),
				SymmAlgorithm.aes128Ccm, encAlg, authTicketEncryptionKeys.getPublic());
		byte[] hmacKey = genHmacKey();
		sharedAtRequest = genDummySharedAtRequest(publicKeys, hmacKey);

		EncryptResult authRequestMessageResult = messagesCaGenerator.genAuthorizationRequestMessage(
				new Time64(new Date()), // generation Time
				publicKeys, hmacKey, sharedAtRequest, enrolmentCredChain, // Certificate chain of enrolment
																			// credential to sign outer message to
																			// AA
				enrolmentCredentialSignKeys.getPrivate(), // Private key used to sign message.
				authTicketSignKeys.getPublic(), // The public key of the auth ticket, used to create POP, null if no POP
												// should be generated.
				authTicketSignKeys.getPrivate(), // The private key of the auth ticket, used to create POP, null if no
													// POP should be generated.
				authorizationCaCert, // The AA certificate to encrypt outer message to.
				enrolmentCaCert, // Encrypt inner ecSignature with given certificate, required if withPrivacy is
									// true.
				true // Encrypt the inner ecSignature message sent to EA
		);
		mySecretKey = authRequestMessageResult.getSecretKey();
		EtsiTs103097DataEncryptedUnicast authRequestMessage = (EtsiTs103097DataEncryptedUnicast) authRequestMessageResult
				.getEncryptedData();
		return authRequestMessage.getEncoded();

	}

	public byte[] sendCAMMessage(byte[] data) throws IllegalArgumentException, IOException, GeneralSecurityException {
		ETSISecuredDataGenerator securedMessageGenerator = new ETSISecuredDataGenerator(ETSISecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaNistP256Signature);
		// To generate a Signed CA Message it is possible to use
		List<HashedId3> hashedId3s = new ArrayList<HashedId3>();
		hashedId3s.add(new HashedId3(cryptoManager.digest(rootCACert.getEncoded(),HashAlgorithm.sha256)));
		hashedId3s.add(new HashedId3(cryptoManager.digest(enrolmentCaCert.getEncoded(),HashAlgorithm.sha256)));
		SequenceOfHashedId3 inlineP2pcdRequest = new SequenceOfHashedId3(hashedId3s);
		byte[] cAMessageData = data;
		EtsiTs103097DataSigned cAMessage = securedMessageGenerator.genCAMessage(new Time64(new Date()), // generationTime
				inlineP2pcdRequest, //  InlineP2pcdRequest (Required)
				rootCACert, // requestedCertificate
				cAMessageData, // inner opaque CA message data
				SecuredDataGenerator.SignerIdentifierType.SIGNER_CERTIFICATE, // signerIdentifierType
				ticket.getCertificate(), // signerCertificate
				authTicketSignKeys.getPrivate()); // signerPrivateKey
	    
// message can be encrypted by using some shared keys (e.g., 211177??)
//		EncryptResult encryptedDataResult = securedMessageGenerator.genEtsiTs103097DataEncrypted(BasePublicEncryptionKeyChoices.ecdsaNistP256,
//				cAMessage.getEncoded(), new Recipient[] {new CertificateRecipient(enrolmentCredCert)});
//		EtsiTs103097DataEncrypted encryptedData = (EtsiTs103097DataEncrypted) encryptedDataResult.getEncryptedData();
		return cAMessage.getEncoded();

	}
	
	/**
	 * Send a message
	 * @return 
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 * @throws GeneralSecurityException 
	 */
	public byte[] sendCAMMessage2(byte[] data) throws IllegalArgumentException, IOException, GeneralSecurityException {
		  // EtsiTs103097Data are created by the Secure Message Generator
				ETSISecuredDataGenerator securedMessageGenerator = new ETSISecuredDataGenerator(ETSISecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256, SignatureChoices.ecdsaNistP256Signature);

				// To generate a Signed CA Message it is possible to use
				List<HashedId3> hashedId3s = new ArrayList<HashedId3>();
				hashedId3s.add(new HashedId3(cryptoManager.digest(rootCACert.getEncoded(),HashAlgorithm.sha256)));
				hashedId3s.add(new HashedId3(cryptoManager.digest(enrolmentCaCert.getEncoded(),HashAlgorithm.sha256)));
			//	SequenceOfHashedId3 inlineP2pcdRequest = new SequenceOfHashedId3(hashedId3s);

//				byte[] cAMessageData = Hex.decode("01020304");
//				EtsiTs103097DataSigned cAMessage = securedMessageGenerator.genCAMessage(new Time64(new Date()), // generationTime
//						inlineP2pcdRequest, //  InlineP2pcdRequest (Required)
//						rootCACert, // requestedCertificate
//						cAMessageData, // inner opaque CA message data
//						SecuredDataGenerator.SignerIdentifierType.SIGNER_CERTIFICATE, // signerIdentifierType
//						ticket.getCertificate(), // signerCertificate
//						authTicketSignKeys.getPrivate()); // signerPrivateKey
//
//
//			
//
//				// The securedMessageGenerator also have methods to generate more general EtsiTs103097Data profiles such as
//				// EtsiTs103097DataSigned, EtsiTs103097DataSignedExternalPayload, EtsiTs103097DataEncrypted and
//				// EtsiTs103097DataSignedAndEncrypted.
//
			    // It is then possible to create a signed message with the following code
			      // First generate a Header with
			    HeaderInfo hi = securedMessageGenerator.genHeaderInfo(
			    		123L, // psid Required,
			    		new Date(), // generationTime Optional
			    		null, // expiryTime Optional
			    		null, // generationLocation Optional
			    		null, // p2pcdLearningRequest Optional
			    		null, // cracaid Optional
			    		null, // crlSeries Optional
			    		null, // encType Type of encryption when encrypting a message with a encryption key references in a signed message instead of a certificate. Optional
			    		null, // encryptionKey Optional
						null, // inlineP2pcdRequest Optional
				null // requestedCertificate Optional
			    		);

			    // This method can be used to sign the data
				EtsiTs103097DataSigned signedData = securedMessageGenerator.genEtsiTs103097DataSigned(hi,
			    		data, // The actual payload message to sign.
			    		SecuredDataGenerator.SignerIdentifierType.HASH_ONLY, // One of  HASH_ONLY, SIGNER_CERTIFICATE, CERT_CHAIN indicating reference data of the signer to include in the message
			    		new EtsiTs103097Certificate[] {ticket.getCertificate(),authorizationCaCert, rootCACert}, // The chain is required even though it isn't included in
			    		  // the message if eventual implicit certificates need to have it's public key reconstructed.
			    		authTicketSignKeys.getPrivate()); // Signing Key
				// It is also possible to generate a EtsiTs103097DataSignedExternalPayload with the genEtsiTs103097DataSignedExternalPayload()
				// method.
				System.out.println("Signed DATA " + signedData);
			    // The message can be encrypted with the method
			      // First construct a list of recipient which have the public key specified either as a symmetric key, certificate or in header of signed data
			      // In this example we will use certificate as reciever, see package org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient for more details.
//				EncryptResult encryptedDataResult = securedMessageGenerator.genEtsiTs103097DataEncrypted(BasePublicEncryptionKeyChoices.ecdsaNistP256,
//			    		  signedData.getEncoded(), new Recipient[] {new CertificateRecipient(enrolmentCredCert)});
//				EtsiTs103097DataEncrypted encryptedData = (EtsiTs103097DataEncrypted) encryptedDataResult.getEncryptedData();
//			    // It is also possible to sign and encrypt in one go.
				EncryptResult encryptedAndSignedMessageResult = securedMessageGenerator.genEtsiTs103097DataSignedAndEncrypted(hi,
			    		data,
			    		SecuredDataGenerator.SignerIdentifierType.HASH_ONLY,
			    		new EtsiTs103097Certificate[] {ticket.getCertificate(),authorizationCaCert, rootCACert},
						authTicketSignKeys.getPrivate(), // Important to use the reconstructed private key for implicit certificates
			    		BasePublicEncryptionKeyChoices.ecdsaNistP256,
			    		new Recipient[] {new CertificateRecipient(enrolmentCredCert)});

				EtsiTs103097DataEncrypted encryptedAndSignedMessage = (EtsiTs103097DataEncrypted) 
						encryptedAndSignedMessageResult.getEncryptedData();
				return encryptedAndSignedMessage.getEncoded();
				
			    
	}
	/**
	 * This is the request for enrollment. The status is Initialized. It flows the
	 * follows:
	 * 
	 * var req = Send_EnrolmentRequest if (req = fail) resend else enrolled
	 * 
	 * The authorization request shall be used in subsequent authorization requests.
	 * This is defined in section 6.2.3.2.1 of the 102 941
	 * 
	 * @param encPk
	 * @return The message to unicast for the root CA
	 * @throws Exception
	 */
	public byte[] requestEnrolment() throws Exception {
		/*
		 * Now I have to create the ECC key (in keys) And the InnerECRequest structure
		 * that contains:
		 * 
		 * The identifier. For a re-enrolment, there is something to do (see the
		 * paragraph)
		 * 
		 * Now I crete the InnerECRequest, with the ID, the certificate format (value 1)
		 * the verification key for the EC, and the desired attribute.
		 */

		PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, enrolmentCredentialSignKeys.getPublic(),
				SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,
				enrolmentCredentialEncryptionKeys.getPublic());

		// The assurance of this ITS-S
		SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);

		// where is my manufacturer?

		// This is the InnerEcRequest. The outer parts are Data-Signed and Encrypted.
		PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(
				ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
		PsidSsp[] appPermissions = new PsidSsp[] { appPermCertMan };

		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
		timeStamp = dateFormat.parse("20181202 12:12:21");

		ValidityPeriod enrolValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 5);

		CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes(
				Inet4Address.getLocalHost().getCanonicalHostName(), enrolValidityPeriod, region, subjectAssurance,
				appPermissions, null);

		InnerEcRequest request = new InnerEcRequest(myID.getBytes("UTF-8"), CertificateFormat.TS103097C131, publicKeys,
				certificateSubjectAttributes);

		initialEnrolRequestMessageResult = messagesCaGenerator.genInitialEnrolmentRequestMessage(new Time64(new Date()), // this
																															// is
																															// the
																															// generation
																															// time
				request, // this is the request
				enrolmentCredentialSignKeys.getPublic(), enrolmentCredentialSignKeys.getPrivate(), enrolmentCaCert); // the
																														// cetificate
																														// for
																														// which
																														// I
																														// have
																														// to
																														// encrypt
																														// to
		System.out.println("Generato un messaggio di richeista di enrolment per enrolCa. Io sono " + myID
				+ " e la richiesta è " + request);
		return initialEnrolRequestMessageResult.getEncryptedData().getEncoded();

	}

	/**
	 * Here I get an enrolment message response, checking if all is ok.
	 * 
	 * @param enrollmentResponse
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws IllegalArgumentException
	 * @throws InternalErrorException
	 * @throws DecryptionFailedException
	 * @throws SignatureVerificationException
	 * @throws MessageParsingException
	 */
	public void finishEnrolment(byte[] enrollmentResponse)
			throws IOException, IllegalArgumentException, GeneralSecurityException, MessageParsingException,
			SignatureVerificationException, DecryptionFailedException, InternalErrorException {

		EtsiTs103097DataEncryptedUnicast enrolResponseMessage = new EtsiTs103097DataEncryptedUnicast(
				enrollmentResponse);

		Map<HashedId8, Certificate> trustStore = messagesCaGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { rootCACert });

		Map<HashedId8, Certificate> enrolCACertStore = messagesCaGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { enrolmentCaCert, rootCACert });
		// Build reciever store containing the symmetric key used in the request.
		Map<HashedId8, Receiver> enrolCredSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[] {
				new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, initialEnrolRequestMessageResult.getSecretKey()) });
		VerifyResult<InnerEcResponse> enrolmentResponseResult = messagesCaGenerator
				.decryptAndVerifyEnrolmentResponseMessage(enrolResponseMessage, enrolCACertStore, // Certificate chain
																									// if EA CA
						trustStore, enrolCredSharedKeyReceivers);
		InnerEcResponse innerResponse = enrolmentResponseResult.getValue();
		System.out.println("Got a inner response for my enrolment request. How do I check the replay? With the hash! ");
		if (innerResponse.getResponseCode().equals(EnrollmentResponseCode.ok)) {
			System.out.println("All is good I'm enrolled! ");
			enrolmentCredCert = innerResponse.getCertificate();
			enrolmentCredChain = new EtsiTs103097Certificate[] { enrolmentCredCert, enrolmentCaCert, rootCACert };
		} else {
			System.out.println("Mmmm, I'm not good, error");
		}
	}

	private CertificateSubjectAttributes genCertificateSubjectAttributes(String hostname, ValidityPeriod validityPeriod,
			GeographicRegion region, SubjectAssurance assuranceLevel, PsidSsp[] appPermissions,
			PsidGroupPermissions[] certIssuePermissions) throws Exception {

		return new CertificateSubjectAttributes(
				(hostname != null ? new CertificateId(new Hostname(hostname)) : new CertificateId()), validityPeriod,
				region, assuranceLevel, new SequenceOfPsidSsp(appPermissions),
				(certIssuePermissions != null ? new SequenceOfPsidGroupPermissions(certIssuePermissions) : null));
	}

	public String getMyID() {
		return myID;
	}

	public DefaultCryptoManager getCryptoManager() {
		return cryptoManager;
	}

	public void setCryptoManager(DefaultCryptoManager cryptoManager) {
		this.cryptoManager = cryptoManager;
	}

	public KeyPair getEnrolmentCredentialSignKeys() {
		return enrolmentCredentialSignKeys;
	}

	public void setEnrolmentCredentialSignKeys(KeyPair enrolmentCredentialSignKeys) {
		this.enrolmentCredentialSignKeys = enrolmentCredentialSignKeys;
	}

	public KeyPair getEnrolmentCredentialEncryptionKeys() {
		return enrolmentCredentialEncryptionKeys;
	}

	public void setEnrolmentCredentialEncryptionKeys(KeyPair enrolmentCredentialEncryptionKeys) {
		this.enrolmentCredentialEncryptionKeys = enrolmentCredentialEncryptionKeys;
	}

	public KeyPair getEnrolmentCredentialReSignKeys() {
		return enrolmentCredentialReSignKeys;
	}

	public void setEnrolmentCredentialReSignKeys(KeyPair enrolmentCredentialReSignKeys) {
		this.enrolmentCredentialReSignKeys = enrolmentCredentialReSignKeys;
	}

	public EtsiTs103097Certificate getRootCACert() {
		return rootCACert;
	}

	public void setRootCACert(EtsiTs103097Certificate rootCACert) {
		this.rootCACert = rootCACert;
	}

	public EtsiTs103097Certificate getEnrolmentCaCert() {
		return enrolmentCaCert;
	}

	public void setEnrolmentCaCert(EtsiTs103097Certificate enrolmentCaCert) {
		this.enrolmentCaCert = enrolmentCaCert;
	}

	public EtsiTs103097Certificate getAuthorizationCaCert() {
		return authorizationCaCert;
	}

	public void setAuthorizationCaCert(EtsiTs103097Certificate authorizationCaCert) {
		this.authorizationCaCert = authorizationCaCert;
	}

	public EtsiTs103097Certificate[] getEnrolmenCredChain() {
		return enrolmentCredChain;
	}

	public void setEnrolmenCredChain(EtsiTs103097Certificate[] enrolmenCredChain) {
		this.enrolmentCredChain = enrolmenCredChain;
	}

	public EtsiTs103097Certificate getEnrolmentCredCert() {
		return enrolmentCredCert;
	}

	public void setEnrolmentCredCert(EtsiTs103097Certificate enrolmentCredCert) {
		this.enrolmentCredCert = enrolmentCredCert;
	}

	public ETSITS102941MessagesCaGenerator getMessagesCaGenerator() {
		return messagesCaGenerator;
	}

	public void setMessagesCaGenerator(ETSITS102941MessagesCaGenerator messagesCaGenerator) {
		this.messagesCaGenerator = messagesCaGenerator;
	}

	public GeographicRegion getRegion() {
		return region;
	}

	public void setRegion(GeographicRegion region) {
		this.region = region;
	}

	public static String getMyid() {
		return myID;
	}

	public KeyPair getAuthTicketSignKeys() {
		return authTicketSignKeys;
	}

	public KeyPair getAuthTicketEncryptionKeys() {
		return authTicketEncryptionKeys;
	}

}
