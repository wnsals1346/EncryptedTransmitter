import javax.swing.*;

/*
 * By JunMin Kim 15146308 ITM SeoulTech
 * Code is 4 part.  Server GUI, Server method, Client GUI, Client method.
 * Most part is same in TransmitterClient.java and TransmitterServer.java
 * I commented almost information on TransmitterServer.java and only difference part is wrote in TransmitterClient.java
 *
 */

public class Main extends JFrame {
    public static void main(String[] args) {
        new TransmitterServer();
        new TransmitterClient();

    }
}