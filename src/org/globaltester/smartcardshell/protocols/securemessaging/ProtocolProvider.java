package org.globaltester.smartcardshell.protocols.securemessaging;

import java.util.List;

import org.globaltester.smartcardshell.protocols.AbstractScshProtocolProvider;
import org.globaltester.smartcardshell.protocols.ScshCommand;
import org.globaltester.smartcardshell.protocols.ScshCommandParameter;

public class ProtocolProvider extends AbstractScshProtocolProvider {

	private static ScshCommand sendCommand;
	{
		sendCommand = new ScshCommand("sendCommand");
		sendCommand.setHelp("Sends an APDU to the card, depending on the current state of SecureMessaging SM is used or not.");
		sendCommand.setHelpReturn("Plain response if response returned by card was valid otherwise an assertion is thrown");

		ScshCommandParameter capduParam = new ScshCommandParameter("cmdAPDU");
		capduParam.setHelp("ByteString(byte[] conatining the plain CommandAPDU to be transmitted");
		sendCommand.addParam(capduParam);

		String impl = "";
		impl += "if (this.gt_SecureMessaging_getSM().isInitialized()) {\n";
		impl += "    return this.gt_sendSM(cmdAPDU);\n";
		impl += "} else {\n";
		impl += "    return this.gt_sendPlain(cmdAPDU);\n";
		impl += "}\n";
		sendCommand.setImplementation(impl);
	}
	
	private static ScshCommand sendSM;
	{
		sendSM = new ScshCommand("sendSM");
		sendSM.setHelp("Wraps the given plain APDU in valid secure messaging, transmits SM-APDU to the card and processes the response");
		sendSM.setHelpReturn("Plain response if response returned by card was valid otherwise an assertion is thrown");

		ScshCommandParameter capduParam = new ScshCommandParameter("cmdAPDU");
		capduParam.setHelp("ByteString containing the plain CommandAPDU to be transmitted");
		sendSM.addParam(capduParam);

		String impl = "";
		impl += "var sm = this.gt_SecureMessaging_getSM();\n";
		
		//log plain command APDU
		impl += "logCmdApdu = \"=> Command APDU [\\n\"+HexString.dump(cmdAPDU)+\"\\n] C-APDU\";\n";
		impl += "print(logCmdApdu);\n";
		
		impl += "var securedCmd = sm.wrapSM(cmdAPDU);\n";
		impl += "var encodedResp = this.gt_sendPlain(securedCmd);\n";
		impl += "var decodedResp = sm.unwrap(encodedResp);\n";
		
		//log plain response APDU
		impl += "logRespApdu = \"<= Response APDU [\\n\"+HexString.dump(decodedResp)+\"\\n] R-APDU\";\n";
		impl += "print(logRespApdu);\n";
		
		
		impl += "return decodedResp;\n";
		sendSM.setImplementation(impl);
	}
	
	private static ScshCommand initSM;
	{
		initSM = new ScshCommand("initSM");
		initSM.setHelp("Initialize Securemessaging with the given keys");
		initSM.setHelpReturn("");

		//sKenc, sKmac, ssc)
		
		ScshCommandParameter sKencParam = new ScshCommandParameter("sKenc");
		sKencParam.setHelp("javax.crypto.SecretKey used for encrypting the Cryptogram of secured APDU");
		initSM.addParam(sKencParam);
		
		ScshCommandParameter sKmacParam = new ScshCommandParameter("sKmac");
		sKmacParam.setHelp("javax.crypto.SecretKey used for generating the MAC of secured APDU");
		initSM.addParam(sKmacParam);

		ScshCommandParameter sscParam = new ScshCommandParameter("ssc");
		sscParam.setHelp("ByteString conatining the initial SendSecuenceCounter");
		initSM.addParam(sscParam);

		
		String impl = "";
		impl += "var sm = this.gt_SecureMessaging_getSM();\n";
		impl += "if (sKenc) sm.setKeyEnc(sKenc);\n";
		impl += "if (sKmac) sm.setKeyMac(sKmac);\n";
		impl += "if (ssc) sm.setSendSequenceCounter(ssc);\n";
		impl += "sm.setInitialized(true);\n";
		initSM.setImplementation(impl);
		
		//FIXME make sure the initialization state is rest when plain APDU is transmitted or card was reset
	}
	
	private static ScshCommand getSM;
	{
		getSM = new ScshCommand("getSM");
		getSM.setHelp("Return the SecureMessaging object associated with this card. This can be used to manipulate the SM bevahior of sendCommand() and sendSM()\n\nThis method behaves like a singleton access method, e.g. if the SM instance does not exist it will be created but several sequential calls to this method will always return the same instance.");
		getSM.setHelpReturn("SecureMessaging object used by this card (Instance of org.globaltester.smartcardshell.protocols.secruremessaging.SecureMessaging");

		String impl = "";
		impl += "if (this.gt_SecureMessaging_SM == undefined) {\n";
		impl += "    print(\"gt_SecureMessaging_SM is not defined yet, will be created now\");\n";
		impl += "    this.gt_SecureMessaging_SM = new Packages.org.globaltester.smartcardshell.protocols.securemessaging.SecureMessaging()";
		impl += "}\n";
		impl += "return this.gt_SecureMessaging_SM;\n";
		getSM.setImplementation(impl);
	}

	@Override
	public void addCommands(List<ScshCommand> commandList) {
		commandList.add(initSM);
		commandList.add(getSM);
		commandList.add(sendSM);
		commandList.add(sendCommand);
	}
	
}
