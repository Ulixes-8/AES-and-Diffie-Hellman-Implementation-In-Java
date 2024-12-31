//This is a simple client that connects to on ip "ipAddy" on  port "portNo" 
// and sends two strings.

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;


public class SocketClient {

	// ipAddy must be changed to the ip address of the server
	static String ipAddy = "localhost";
	static int portNo = 11337;

	public static void main(String[] args) throws IOException {
		
		System.out.println("opening socket");
		Socket socket = new Socket(ipAddy,portNo);
		
		//Wrapping a PrintWriter around the output streams lets us to write strings
		PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
		
		System.out.println("writing data");
		out.write("username: tpc \n");
		out.write("password: kFS74ga*@%*Bna\n");
		out.flush();
        // Sleep for 10 seconds
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
		System.out.println("closing socket");		
		socket.close();

		System.out.println("done");
	}
}












