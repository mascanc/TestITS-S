package it.mascanc.its.security;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;

/**
 * This is the root CA mock. It starts a server listening on port 8886. The
 * reference standard is <a href=
 * "https://www.etsi.org/deliver/etsi_ts/103000_103099/103097/01.03.01_60/ts_103097v010301p.pdf">Here</a>
 * 
 * It is defined in 102 940 as the The Root CA is the highest level CA in the
 * certification hierarchy. Itprovides EA and AA with proof that it may issue
 * enrolment credentials, respectively authorization tickets
 * 
 * @author max
 *
 */
public class RootCA implements Runnable {
	public static final int port = 8886;

	private EtsiTs103097Certificate myCertificate;

	private KeyPair rootCASigningKeys;

	private KeyPair rootCAEncryptionKeys;

	private Ieee1609Dot2CryptoManager cryptoManager;

	private EtsiTs103097Certificate enrolmentCaCertificate;

	/*
	 * Crypto stuff for the ENROLMENT CA
	 */
	private KeyPair enrollmentCAEncryptionKeys;

	private KeyPair enrollmentCASigningKeys;

	private EtsiTs103097Certificate enrollmentCACertificate;

	private EtsiTs103097Certificate[] enrollmentCAChain;

	/*
	 * Crypto stuff for the AUTHORIZATION CA
	 */

	private KeyPair authorizationCAEncryptionKeys;

	private KeyPair authorizationCASigningKeys;

	private EtsiTs103097Certificate authorizationCACertificate;

	private EtsiTs103097Certificate[] authorizationCaChain;
	
	
	public EtsiTs103097Certificate getRootCACertificate() {
		return this.myCertificate;
	}

	public RootCA() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException, InvalidKeyException {

		/*
		 * Set the Root CA according with ETSI 103 097
		 */

		// Create a crypto manager in charge of communicating with underlying
		// cryptographic components
		cryptoManager = new DefaultCryptoManager();
		// Initialize the crypto manager to use soft keys using the bouncy castle
		// cryptographic provider.
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

		this.myCertificate = createRootCaCertificate();
//		CacheHolder.getInstance().add(Constants.ROOT_CA_CERTIFICATE, this.myCertificate);
		System.out.println("Created Root CA");

		createEnrolmentCaCertificate();
	//	CacheHolder.getInstance().add(Constants.ENROLMENT_CA_CERTIFICATE, this.enrolmentCaCertificate);
		System.out.println("Created Enrolment CA");

		createAuthorizationCaCertificate();
		//CacheHolder.getInstance().add(Constants.AUTHORIZATION_CA_CERTIFICATE, this.enrolmentCaCertificate);
		System.out.println("Created Authorization CA");
	}

	public void run() {
		System.out.println("Root CA Server starting");
		try (ServerSocket mySocket = new ServerSocket(port)) {
			while (true) {

				System.out.println("Waiting RootCA on port " + port);
				Socket clientSocket = mySocket.accept();
				System.out.println("Obtained client connection from: " + clientSocket.getInetAddress());
				DataInputStream dis=new DataInputStream(clientSocket.getInputStream());  
				String data = dis.readUTF();
				System.out.println(data);
			//	process(data);
			}
		} catch (Throwable e) {
			throw new IllegalStateException(e);

		}

	}
//	
//	void process(String data) throws InterruptedException {
//		if (data.equals(Constants.SITS_INITIAL_DATA)) {
//			System.out.println("Reading the SITS initial data");
//		//	CAandID caAndId = (CAandID)CacheHolder.getInstance().get(Constants.SITS_INITIAL_DATA);
//			System.out.println("Read data for ITS-S " + caAndId.getMyID());
//		}
//	}

	/**
	 * Something to say: according with ETSI, the data structures are in ASN.1
	 * encoded using COER, the Canonical Octect Encoding Rules (sic!). The data
	 * structure is of type Ieee1609Dot2Data (the reason of the crypto manager). The
	 * idea is that the data structure EtsiTs103097Data is the same as iee.
	 * 
	 * A certificate contains signedData, encryptedData, and unsecuredData
	 * 
	 * The definition of the root CA is defined in clause 7.2.3.
	 * 
	 * For the root ca, the issuer shall be self. But for authority link certificate
	 * (WHAT IT IS?) the issuer shalol be set to sha256anddigest. The toBeSigned
	 * data shall contain the certIssuePermissions shall contain the permissions to
	 * sign subordinate certification authorities. The appPermissions shall be used
	 * to indicate permissions to sign: CRLs and contains the ITS AID for the CRL as
	 * assigned in ETSI TS 102 965 CTL.
	 * 
	 * In ETSI TS 102 965
	 * https://www.etsi.org/deliver/etsi_ts/102900_102999/102965/01.03.01_60/ts_102965v010301p.pdf,
	 * si parla di AID, Application Object Identifier. However the technical issues
	 * of GUIA, it is defined in CEN/ISO TS 17419:2018, which is based on the ITS
	 * station as specified in ISO 21217:2014 (strasic!)
	 * 
	 * @return
	 */
	public EtsiTs103097Certificate createRootCaCertificate()
			throws SignatureException, InvalidKeyException, IllegalArgumentException, IOException {
		// Create an authority certificate generator and initialize it with the crypto
		// manager.
		ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);

		// Generate a reference to the Root CA Keys
		rootCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		rootCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		// Defined in section 6.

		ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 45);

		// this is defined in IEEE Std 1609. For italy we have:
		// https://www.iso.org/obp/ui/#iso:code:3166:IT

		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION);
		GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);

		// Generate the root CA Certificate, without any encryption keys or geographic
		// region.
		/*
		 * What I don't know: the minChainDepth and the chainDepthRange. The EC is
		 * mandated by the standard. The CTL is the Certificate Trust List, I don't know
		 * what is the 0138.
		 */
		EtsiTs103097Certificate rootCACertificate = authorityCertGenerator.genRootCA("testrootca.autostrade.it", // caName
				rootCAValidityPeriod, // ValidityPeriod
				region, // GeographicRegion
				3, // minChainDepth
				-1, // chainDepthRange
				Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
				SignatureChoices.ecdsaNistP256Signature, // signingPublicKeyAlgorithm
				rootCASigningKeys.getPublic(), // signPublicKey
				rootCASigningKeys.getPrivate(), // signPrivateKey
				SymmAlgorithm.aes128Ccm, // symmAlgorithm
				BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
				rootCAEncryptionKeys.getPublic()); // encPublicKey
		return rootCACertificate;
	}

	/**
	 * Here I create the certificate of the enrolment CA, which is giving the
	 * certificates to all of the ITS stations.
	 * 
	 * @return
	 * @throws IllegalArgumentException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws InvalidKeyException
	 */
	private void createEnrolmentCaCertificate()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException {

		ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);
		// Generate a reference to the Enrollment CA Keys
		enrollmentCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		enrollmentCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		//CacheHolder.getInstance().add(Constants.ENROLMENT_CA_SIGNING_KEYS, enrollmentCASigningKeys);

		// This is a very long term certificate!!!!!
		ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 37);
		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION);
		GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);
		// Generate a reference to the Enrollment CA Signing Keys
		enrollmentCACertificate = authorityCertGenerator.genEnrollmentCA("testea.autostrade.it", // CA
				// Name
				enrollmentCAValidityPeriod, region, // GeographicRegion
				new SubjectAssurance(1, 3), // subject assurance (optional)
				SignatureChoices.ecdsaNistP256Signature, // signingPublicKeyAlgorithm
				enrollmentCASigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
				myCertificate, // signerCertificate
				rootCASigningKeys.getPublic(), // signCertificatePublicKey, must be specified separately to support
												// implicit certificates.
				rootCASigningKeys.getPrivate(), SymmAlgorithm.aes128Ccm, // symmAlgorithm
				BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
				enrollmentCAEncryptionKeys.getPublic() // encryption public key
		);
        enrollmentCAChain = new EtsiTs103097Certificate[]{enrollmentCACertificate,myCertificate};

	}

	public KeyPair getEnrollmentCAEncryptionKeys() {
		return enrollmentCAEncryptionKeys;
	}

	public void setEnrollmentCAEncryptionKeys(KeyPair enrollmentCAEncryptionKeys) {
		this.enrollmentCAEncryptionKeys = enrollmentCAEncryptionKeys;
	}

	private void createAuthorizationCaCertificate()
			throws IllegalArgumentException, SignatureException, IOException, InvalidKeyException {

		ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);

		// Generate a reference to the Authorization CA Keys
		authorizationCASigningKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);
		authorizationCAEncryptionKeys = cryptoManager.generateKeyPair(SignatureChoices.ecdsaNistP256Signature);

		ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), DurationChoices.years, 15);
		List<Integer> countries = new ArrayList<Integer>();
		countries.add(Constants.REGION);
		GeographicRegion region = GeographicRegion.generateRegionForCountrys(countries);

		// Generate a reference to the Authorization CA Signing Keys
		authorizationCACertificate = authorityCertGenerator.genAuthorizationCA(
				"testaa.autostrade.it", // CA Name
				authorityCAValidityPeriod, region, // GeographicRegion
				new SubjectAssurance(1, 3), // subject assurance (optional)
				SignatureChoices.ecdsaNistP256Signature, // signingPublicKeyAlgorithm
				authorizationCASigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
				myCertificate, // signerCertificate
				rootCASigningKeys.getPublic(), // signCertificatePublicKey,
				rootCASigningKeys.getPrivate(), SymmAlgorithm.aes128Ccm, // symmAlgorithm
				BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
				authorizationCAEncryptionKeys.getPublic() // encryption public key
		);
		authorizationCaChain = new EtsiTs103097Certificate[]{authorizationCACertificate,myCertificate};

	}



	public EtsiTs103097Certificate getMyCertificate() {
		return myCertificate;
	}

	public void setMyCertificate(EtsiTs103097Certificate myCertificate) {
		this.myCertificate = myCertificate;
	}

	public KeyPair getRootCASigningKeys() {
		return rootCASigningKeys;
	}

	public void setRootCASigningKeys(KeyPair rootCASigningKeys) {
		this.rootCASigningKeys = rootCASigningKeys;
	}

	public KeyPair getRootCAEncryptionKeys() {
		return rootCAEncryptionKeys;
	}

	public void setRootCAEncryptionKeys(KeyPair rootCAEncryptionKeys) {
		this.rootCAEncryptionKeys = rootCAEncryptionKeys;
	}

	public Ieee1609Dot2CryptoManager getCryptoManager() {
		return cryptoManager;
	}

	public void setCryptoManager(Ieee1609Dot2CryptoManager cryptoManager) {
		this.cryptoManager = cryptoManager;
	}

	public EtsiTs103097Certificate getEnrolmentCaCertificate() {
		return enrolmentCaCertificate;
	}

	public void setEnrolmentCaCertificate(EtsiTs103097Certificate enrolmentCaCertificate) {
		this.enrolmentCaCertificate = enrolmentCaCertificate;
	}

	public KeyPair getEnrollmentCASigningKeys() {
		return enrollmentCASigningKeys;
	}

	public void setEnrollmentCASigningKeys(KeyPair enrollmentCASigningKeys) {
		this.enrollmentCASigningKeys = enrollmentCASigningKeys;
	}

	public EtsiTs103097Certificate getEnrollmentCACertificate() {
		return enrollmentCACertificate;
	}

	public void setEnrollmentCACertificate(EtsiTs103097Certificate enrollmentCACertificate) {
		this.enrollmentCACertificate = enrollmentCACertificate;
	}

	public EtsiTs103097Certificate[] getEnrollmentCAChain() {
		return enrollmentCAChain;
	}

	public void setEnrollmentCAChain(EtsiTs103097Certificate[] enrollmentCAChain) {
		this.enrollmentCAChain = enrollmentCAChain;
	}

	public static int getPort() {
		return port;
	}

	public KeyPair getAuthorizationCAEncryptionKeys() {
		return authorizationCAEncryptionKeys;
	}

	public void setAuthorizationCAEncryptionKeys(KeyPair authorizationCAEncryptionKeys) {
		this.authorizationCAEncryptionKeys = authorizationCAEncryptionKeys;
	}

	public KeyPair getAuthorizationCASigningKeys() {
		return authorizationCASigningKeys;
	}

	public void setAuthorizationCASigningKeys(KeyPair authorizationCASigningKeys) {
		this.authorizationCASigningKeys = authorizationCASigningKeys;
	}

	public EtsiTs103097Certificate getAuthorizationCACertificate() {
		return authorizationCACertificate;
	}

	public void setAuthorizationCACertificate(EtsiTs103097Certificate authorizationCACertificate) {
		this.authorizationCACertificate = authorizationCACertificate;
	}

	public EtsiTs103097Certificate[] getAuthorizationCAChain() {
		return authorizationCaChain;
	}

	public void setAuthorizationCAChain(EtsiTs103097Certificate[] authorizationCAChain) {
		this.authorizationCaChain = authorizationCAChain;
	}
	
}
