package org.globaltester.smartcardshell.protocols.securemessaging;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IConfigurationElement;
import org.globaltester.smartcardshell.protocols.IScshProtocolProvider;

public class ProtocolProvider implements IScshProtocolProvider {

	public static final String SEND_COMMAND = "sendCommand";
	public static final String SEND_SM = "sendSM";
	private static ArrayList<String> commands;

	public ProtocolProvider() {
		// required constructor for the construction during extension point
		// usage
	}

	@Override
	public Collection<String> getCommands() {
		if (commands == null) {
			commands = new ArrayList<String>();
			commands.add(SEND_COMMAND);
			commands.add(SEND_SM);
		}
		return commands;
	}

	@Override
	public List<String> getParams(String command) {
		if (!getCommands().contains(command)) {
			return null;
		} else if (SEND_COMMAND.equals(command)) {
			ArrayList<String> params = new ArrayList<String>();
			params.add("cmdAPDU");
			return params;
		} else if (SEND_SM.equals(command)) {
			ArrayList<String> params = new ArrayList<String>();
			params.add("cmdAPDU");
			params.add("keyIdEnc");
			params.add("keyIdMac");
			return params;
		} else {
			return new ArrayList<String>();
		}
	}

	@Override
	public String getImplementation(String command) {
		if (!getCommands().contains(command)) {
			return null;
		} else if (SEND_COMMAND.equals(command)) {
			String cmd = "";
			cmd += "print(\"send_command\");\n";
			cmd += "return this.gt_sendPlain(cmdAPDU);\n";
			return cmd;
		} else if (SEND_SM.equals(command)) {
			String cmd = "";
			cmd += "print(\"send_command\");\n";
			cmd += "return this.gt_sendPlain(cmdAPDU);\n";
			return cmd;
		} else {
			return "";
		}
	}

	@Override
	public String getHelp(String command) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getHelpReturn(String command) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getHelpParam(String command, String parameter) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setInitializationData(IConfigurationElement config,
			String propertyName, Object data) throws CoreException {
		// intentionally left empty, the provided data is of no use in this extension
		
	}

}
