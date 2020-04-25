package it.mascanc.its.security;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

public class CAandID {
	private EtsiTs103097Certificate publicKey;
	private String myID;

	public CAandID(String myID, EtsiTs103097Certificate etsiTs103097Certificate) {
		this.publicKey = etsiTs103097Certificate;
		this.myID = myID;
		
	}

	public EtsiTs103097Certificate getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(EtsiTs103097Certificate publicKey) {
		this.publicKey = publicKey;
	}

	public String getMyID() {
		return myID;
	}

	public void setMyID(String myID) {
		this.myID = myID;
	}
	
}
