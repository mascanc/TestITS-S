package it.mascanc.its.security;

public class Main {

	/**
	 * This is the main class for the test.
	 * 
	 * It should start a the following services:
	 * <ol>
	 * <li>A sending ITS station (this thread)</li>
	 * <li>A receiving ITS station</li>
	 * <li>A Enrollment Authority EA</li>
	 * <li>A Authorization Authority</li>
	 * <li>A root CA</li>
	 * </ol>
	 * After setting up all the threads it starts sending messages according with
	 * the relevant standards. Namely we have the following
	 * <ul>
	 * <li><b>Architecture</b>: 102 940</li>
	 * <li><b>Trust & Communication</b>: 102 731</li>
	 * <li><b>Message Format</b> related to the certificates, CA and DENM: 103
	 * 097</li>
	 * <li><b>Data Structure</b> such as Enrol Req/resp, Authz Req Resp, Authz Val
	 * Req/Resp: 102 941</li>
	 * </ul>
	 * 
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args)
			throws Exception {


		// First of all we create a RootCA
		RootCA rootCa = new RootCA();

		// Then we create an enrolment CA
		EnrollmentCA enrollmentCA = new EnrollmentCA();
		enrollmentCA.setCertificate(rootCa.getEnrollmentCACertificate());
		enrollmentCA.setSigningKeys(rootCa.getEnrollmentCASigningKeys());
		enrollmentCA.setEncrptionKeys(rootCa.getEnrollmentCAEncryptionKeys());
		enrollmentCA.setEnrolmentCAChain(rootCa.getEnrollmentCAChain());
		
		
			
		// Now I need to create the autorhization CA
		AuthorizationCA authorizationCA = new AuthorizationCA();
//		authorizationCA.setRootCaCert(rootCa.getRootCACertificate());
		authorizationCA.setCertificate(rootCa.getAuthorizationCACertificate());
		authorizationCA.setSigningKeys(rootCa.getAuthorizationCASigningKeys());
		authorizationCA.setEncryptionKeys(rootCa.getAuthorizationCAEncryptionKeys());
		authorizationCA.setAuthorizationCaChain(rootCa.getAuthorizationCAChain());
	
		
		/*
		 * The security lifecycle of an ITS-S is 
		 * Before init
		 * Initialisation and Unenrolled
		 * Enrolled and Unauthorised
		 * Authorised for service
		 * EOL
		 * 
		 * This is defined in page 12 of ETSI TS 102 941 v 1.3.1
		 * 
		 */
		
		// This is the sending ITS-S (e.g., a RSE)
		SendingITS sits = new SendingITS();
		sits.setEnrolmentCaCert(enrollmentCA.getCertificate());
		sits.setAuthorizationCaCert(authorizationCA.getCertificate());
		sits.setRootCACert(rootCa.getRootCACertificate());
		

		// Devo dare all'enrolment CA la mia chiave pubblica. Le credenziali sono create dal manufacturer
		// e passate tramite un canale sicuro (102 941)
		// Non mi prendete in giro per l'IPC :)
		
		// sent my ID to the enrolment CA, simulating an OOB channel
		CAandID sits_ca_and_id = new CAandID(sits.getMyID(),sits.getEnrolmentCredCert());
		enrollmentCA.setSitsId(sits_ca_and_id);
	
		/*
		 * ENROLMENT
		 */
		byte[] enrolmentMSgToSendToEnrolmentCA = sits.requestEnrolment();
		// Ora lo devo mandare a EnrolCA
		byte[] enrollmentResponse = enrollmentCA.enrollITS(enrolmentMSgToSendToEnrolmentCA);
		sits.finishEnrolment(enrollmentResponse);
		
		
		/*
		 * AUTHORIZATION
		 */
		// Set some certificate chain
//		authorizationCA.setEnrollmentCredCertChain(sits.getEnrolmenCredChain());
//		authorizationCA.setEnrolCAEncKeys(enrollmentCA.getEncryptionKeys());
//		authorizationCA.setEnrolmentCACert(enrollmentCA.getCertificate());

		byte[] authorizationMsgToSendToAuthorizationCA = sits.requestAuthorizationFor("CAM");
		authorizationCA.setAuthTicketEncKeysPublicKey(sits.getAuthTicketEncryptionKeys().getPublic());
		authorizationCA.setAuthTicketSignKeysPublicKey(sits.getAuthTicketSignKeys().getPublic());
		byte[] authorizationResponse = authorizationCA.authorize(authorizationMsgToSendToAuthorizationCA);
		sits.setAuthorizationTicket(authorizationResponse);
		
		/*
		 * Now, if I am here without any exception, I am ready to send a message
		 */
		byte[] cam = sits.sendCAMMessage("Ciao".getBytes());
		
		ReceivingITS ritss = new ReceivingITS();
		ritss.setAuthorityCACertificate(authorizationCA.getCertificate());
		ritss.setRootCACertificate(rootCa.getMyCertificate());
		String received = ritss.receive(cam);
		System.out.println("Received: " + received);
		System.out.println("Closing everything");

	}

//	private static void send(String message, int port) throws UnknownHostException, IOException {
//		Socket socket = new Socket("localhost", port);
//
//		DataOutputStream dout=new DataOutputStream(socket.getOutputStream());
//		dout.write(message.getBytes());
//		dout.flush();
//		dout.close();
//		socket.close();
//		
//	}
//	
	
}
