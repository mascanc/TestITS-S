package it.mascanc.its.security;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Map;

import org.certificateservices.custom.c2x.common.crypto.BadCredentialsException;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

/**
 * Simulates a receiving ITS-S, e.g., a OBE
 * It receives a CAM (signed) and validates it. 
 * @author max
 *
 */
public class ReceivingITS {

	private DefaultCryptoManager cryptoManager;
	private EtsiTs103097Certificate rootCACertificate;
	private EtsiTs103097Certificate authorityCACertificate;

	public EtsiTs103097Certificate getRootCACertificate() {
		return rootCACertificate;
	}

	public void setRootCACertificate(EtsiTs103097Certificate rootCACertificate) {
		this.rootCACertificate = rootCACertificate;
	}

	

	public ReceivingITS() throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, IOException, BadCredentialsException {
		cryptoManager = new DefaultCryptoManager();
		// Initialize the crypto manager to use soft keys using the bouncy castle
		// cryptographic provider.
		cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
	}

	public String receive(byte[] data) throws IllegalArgumentException, IOException, GeneralSecurityException {
		EtsiTs103097DataSigned cam = new EtsiTs103097DataSigned(data);

		ETSISecuredDataGenerator securedMessageGenerator = new ETSISecuredDataGenerator(
				ETSISecuredDataGenerator.DEFAULT_VERSION, cryptoManager, HashAlgorithm.sha256,
				SignatureChoices.ecdsaNistP256Signature);

		// To decrypt and verify a signed message it is possible to use the following
		// First build a truststore of trust anchors (root CA certificate or equivalent)
		Map<HashedId8, Certificate> trustStore = securedMessageGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { rootCACertificate });
		// Second build a store of known certificate that might be referenced in the
		// message.
		
		Map<HashedId8, Certificate> certStore = securedMessageGenerator
				.buildCertStore(new EtsiTs103097Certificate[] { authorityCACertificate });

	
		boolean back = securedMessageGenerator.verifySignedData(cam, certStore, trustStore);
		
		if (back) {
			System.out.println("HOOORAY! Signature is valid! ");
		}
		else {
			throw new IllegalStateException("Siggnature validation failed");
		}
		
		return cam.getContent().getValue().toString();
	}

	public EtsiTs103097Certificate getAuthorityCACertificate() {
		return authorityCACertificate;
	}

	public void setAuthorityCACertificate(EtsiTs103097Certificate authorityCACertificate) {
		this.authorityCACertificate = authorityCACertificate;
	}

}
