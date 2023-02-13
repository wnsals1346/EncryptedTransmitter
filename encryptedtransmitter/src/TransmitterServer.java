import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


/*
* By JunMin Kim 15146308 ITM SeoulTech
* Code is 4 part.  Server GUI, Server method, Client GUI, Client method.
* Most part(97%) is same in TransmitterClient.java and TransmitterServer.java
* I commented almost information on TransmitterServer.java and only difference part is wrote in TransmitterClient.java
*
 */
class TransmitterServer extends JFrame {
    JPanel jp1, jp2, jp3, jp4, modeSelectPanel, connectPanel, ipPanel, portPanel, btnPanel, msgPanel, aESKeyPanel, aPanel, rSAKeyPanel, rPanel, puKeyPanel, fPanel, fCPanel;
    JLabel ipLabel, portLabel, cModeLabel, connectStateLabel, aESKeyLabel, rSAKeyLabel, prRSAKeyLabel, puRSAKeyLabel, prLabel, puLabel, puKeyLabel, serverLabel;
    JTextField portField, msgField, fileField;
    JButton waitBtn, sendPuRSAKeyBtn, sendAESKeyBtn, loadKeyBtn, saveKeyBtn, genAESKeyBtn, genRSAKeyBtn, sendFileBtn, receiveFileBtn;
    JCheckBox encryptMsgCheck, encryptFileCheck, dSCheck;
    EtchedBorder eBorder;
    BevelBorder bBorder;
    JTextArea textArea;
    JScrollPane textScrollPane, puKeyTableScrollPane;
    JComboBox<Object> aESKeyBox;
    JTable puKeyTable;
    JFileChooser jFileChooser;
    DefaultTableModel model;
    KeyBtnHandler kbh;
    ConnectHandler ch;
    EncryptFileHandler efh;
    EncryptMsgHandler emh;
    DSHandler dsh;

    String header[] = {"Index", "Name", "Key"};
    String contents[][] = new String[5][3];
    final String WARNINGRSA = "***WARNINGRSA***";
    final String WARNINGAES = "***WARNINGAES***";

    int port = 0;
    ServerSocket ss;
    Socket cs;
    DataInputStream in, inf;
    DataOutputStream out, outf;
    FileOutputStream fos;
    FileInputStream fis;





    Sv sv = new Sv();
    //Transmitter GUI Server and Client are almost same.
    TransmitterServer() {
        super("Encrypted Transmitter (Server)");
        setSize(485, 710);
        setLocation(150, 50);
        setResizable(true);
        setVisible(true);
        setLayout(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);   //Basic setting

        eBorder = new EtchedBorder(EtchedBorder.RAISED);
        bBorder = new BevelBorder(BevelBorder.RAISED);

        jp1 = new JPanel(new BorderLayout());
        jp1.setBorder(bBorder); // Panel for Connection part
        jp2 = new JPanel(new BorderLayout());
        jp2.setBorder(bBorder); // Panel for Connect State part
        jp3 = new JPanel(null);
        jp3.setBorder(bBorder); // Panel for All key and files receiving and sending part
        jp4 = new JPanel(new BorderLayout());
        jp4.setBorder(bBorder); // Panel for Chat and SYSTEM Message part.  Most err message and notice is showed here.


        jp1.setBounds(5, 5, 460, 80);
        add(jp1);
        jp2.setBounds(5, 90, 460, 40);
        add(jp2);
        jp3.setBounds(5, 135, 460, 330);
        add(jp3);
        jp4.setBounds(5, 470, 460, 190);
        add(jp4); //Size


        //jp1
        //jp1 - modeSelectPanel
        modeSelectPanel = new JPanel(new BorderLayout());
        modeSelectPanel.setBorder(eBorder);

        cModeLabel = new JLabel("Communication Mode", JLabel.CENTER);
        serverLabel = new JLabel("SERVER", JLabel.CENTER);
        modeSelectPanel.add(cModeLabel, BorderLayout.NORTH);
        modeSelectPanel.add(serverLabel, BorderLayout.CENTER);

        //jp1 - connectPanel
        connectPanel = new JPanel(null);
        connectPanel.setBorder(eBorder);

        ipPanel = new JPanel();
        ipPanel.setPreferredSize(new Dimension(100, 18));
        portPanel = new JPanel();
        portPanel.setPreferredSize(new Dimension(100, 18));
        ipLabel = new JLabel("Server IP : " + sv.localhost, JLabel.LEFT); //show server IP Address
        ipLabel.setPreferredSize(new Dimension(150, 15));
        portLabel = new JLabel("Port :", JLabel.LEFT);
        portLabel.setPreferredSize(new Dimension(30, 15));
        portField = new JTextField(5);  // Server can choose port number to connect
        ipPanel.add(ipLabel);
        portPanel.add(portLabel);
        portPanel.add(portField);
        waitBtn = new JButton("Waiting"); // waiting client Button
        ipPanel.setBounds(28, 5, 150, 35);
        portPanel.setBounds(3, 40, 150, 35);
        waitBtn.setBounds(180, 40, 90, 25);
        ch = new ConnectHandler();
        waitBtn.addActionListener(ch);
        connectPanel.add(ipPanel);
        connectPanel.add(portPanel);
        connectPanel.add(waitBtn);

        jp1.add(modeSelectPanel, BorderLayout.WEST);
        jp1.add(connectPanel, BorderLayout.CENTER);

        //jp2 - Connection State Panel
        connectStateLabel = new JLabel("Waiting for Connection");
        connectStateLabel.setBorder(eBorder);
        connectStateLabel.setOpaque(true);
        connectStateLabel.setBackground(Color.GRAY);
        connectStateLabel.setForeground(Color.WHITE);
        jp2.add(connectStateLabel, BorderLayout.CENTER);

        //jp3
        //jp3 - Key List
        kbh = new KeyBtnHandler();
        aESKeyPanel = new JPanel(new BorderLayout());
        aESKeyLabel = new JLabel("AES key information ");
        aESKeyBox = new JComboBox();

        aPanel = new JPanel(new GridLayout(1, 2));
        genAESKeyBtn = new JButton("AES Key Generation");            // User can select one AES key and send to other
        sendAESKeyBtn = new JButton("Send AES key encrypted with RSA"); // But User need RSA key for encrypting AES Key while transferring
        genAESKeyBtn.addActionListener(kbh);
        sendAESKeyBtn.addActionListener(kbh);
        aPanel.add(genAESKeyBtn);
        aPanel.add(sendAESKeyBtn);

        aESKeyPanel.add(aESKeyLabel, BorderLayout.NORTH);
        aESKeyPanel.add(aESKeyBox, BorderLayout.CENTER);
        aESKeyPanel.add(aPanel, BorderLayout.SOUTH);
        aESKeyPanel.setBorder(eBorder);

        rSAKeyPanel = new JPanel(new BorderLayout());
        rSAKeyLabel = new JLabel("RSA key information - Base64 encoded");  //Show the RSA key pair mady by user. encoded by Base64
        rSAKeyLabel.setBorder(eBorder);                                         //so, even if user have same key, key can be seen different.
        rPanel = new JPanel(new FlowLayout());
        puRSAKeyLabel = new JLabel("Public Key : ");
        prRSAKeyLabel = new JLabel("Private Key : ");
        puLabel = new JLabel();
        prLabel = new JLabel();
        rPanel.add(puRSAKeyLabel);
        rPanel.add(puLabel);
        rPanel.add(prRSAKeyLabel);
        rPanel.add(prLabel);
        rSAKeyPanel.add(rSAKeyLabel, BorderLayout.NORTH);
        rSAKeyPanel.add(rPanel, BorderLayout.CENTER);
        rSAKeyPanel.setBorder(eBorder);

        puKeyPanel = new JPanel(new BorderLayout());
        puKeyLabel = new JLabel("User's Public RSA key information ");   //Other User's Public RSA key List, saved when User receive public key.
        model = new DefaultTableModel(contents, header);
        puKeyTable = new JTable(model);
        puKeyTable.setEnabled(false);
        puKeyTable.getColumn("Index").setPreferredWidth(50);
        puKeyTable.getColumn("Name").setPreferredWidth(100);
        puKeyTable.getColumn("Key").setPreferredWidth(300);

        puKeyTableScrollPane = new JScrollPane(puKeyTable);
        puKeyPanel.add(puKeyLabel, BorderLayout.NORTH);
        puKeyPanel.add(puKeyTableScrollPane, BorderLayout.CENTER);
        puKeyPanel.setBorder(eBorder);


        genRSAKeyBtn = new JButton("RSA Key Generation");   // Can generate RSA key pair and
        sendPuRSAKeyBtn = new JButton("Send public RSA key"); // Send only public key
        loadKeyBtn = new JButton("Load Key from a file");  //also, can load from file or save into file
        saveKeyBtn = new JButton("Save Key into a file"); //always saved at C:
        genRSAKeyBtn.addActionListener(kbh);
        sendPuRSAKeyBtn.addActionListener(kbh);
        loadKeyBtn.addActionListener(kbh);
        saveKeyBtn.addActionListener(kbh);


        //File Part
        emh = new EncryptMsgHandler();
        efh = new EncryptFileHandler();
        dsh = new DSHandler();
        fPanel= new JPanel();
        fCPanel = new JPanel();
        fileField = new JTextField("File",4);
        fileField.setEditable(false);
        receiveFileBtn = new JButton("Recieve");
        receiveFileBtn.setPreferredSize(new Dimension(90,20));
        sendFileBtn = new JButton("Send");  // Server and client can share file and use digital signature for checking
        sendFileBtn.setPreferredSize(new Dimension(65,20));  //also can encrypt and decrypt file when transfer it
        sendFileBtn.setEnabled(false);
        jFileChooser = new JFileChooser("./key");
        jFileChooser.setAcceptAllFileFilterUsed(false);
        jFileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        add(jFileChooser);


        encryptFileCheck = new JCheckBox("En/Decrypt");
        dSCheck = new JCheckBox("RSA Signature");
        encryptFileCheck.addItemListener(efh);
        dSCheck.addItemListener(dsh);
        fPanel.add(receiveFileBtn);
        fPanel.add(fileField);
        fPanel.add(sendFileBtn);
        fCPanel.add(encryptFileCheck);
        fCPanel.add(dSCheck);
        receiveFileBtn.addActionListener(kbh);
        sendFileBtn.addActionListener(kbh);



        btnPanel = new JPanel(new GridLayout(3, 2));

        btnPanel.add(genRSAKeyBtn);
        btnPanel.add(sendPuRSAKeyBtn);
        btnPanel.add(saveKeyBtn);
        btnPanel.add(loadKeyBtn);
        btnPanel.add(fPanel);
        btnPanel.add(fCPanel);


        aESKeyPanel.setBounds(5, 5, 450, 80);
        rSAKeyPanel.setBounds(5, 85, 450, 50);
        puKeyPanel.setBounds(5, 135, 450, 110);
        btnPanel.setBounds(5, 250, 450, 75);
        jp3.add(aESKeyPanel);
        jp3.add(rSAKeyPanel);
        jp3.add(puKeyPanel);
        jp3.add(btnPanel);


        //jp4 Chat part
        textArea = new JTextArea();
        textArea.setEditable(false);

        DefaultCaret caret = (DefaultCaret)textArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);   //Scrollbar is always updated to bottom

        textScrollPane = new JScrollPane(textArea);
        msgPanel = new JPanel(new BorderLayout());
        msgField = new JTextField();
        encryptMsgCheck = new JCheckBox("En/Decrypted with AES");  // User can use En/Decryted mode while chatting with shared AES key.
        msgField.addActionListener(ch);
        encryptMsgCheck.addItemListener(emh);
        msgPanel.add(msgField, BorderLayout.CENTER);
        msgPanel.add(encryptMsgCheck, BorderLayout.EAST);
        jp4.add(textScrollPane, BorderLayout.CENTER);
        jp4.add(msgPanel, BorderLayout.SOUTH);


        jp3.setVisible(false);
        jp4.setVisible(false);


        validate();
    }

    //Server Class
    class Sv implements Runnable {
        InetAddress inetAddress;
        Thread sv1;
        int idx = 1;
        PublicKey pubk;
        PrivateKey prik;
        int flag = 0;

        {
            try {
                inetAddress = InetAddress.getLocalHost();
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        }

        String localhost = inetAddress.getHostAddress();//show Server current IP

        void svThread() {  // Use Thread because of receiving part and waiting connection
            try {
                sv1 = new Thread(this);
                sv1.start();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void run() {
            if (flag == 0) { // only when first time, run connection
                waitingClient();
                receiveMessage();

            } else {  //after connecting, using for control btween sharing message and sharing file. Use same socket
                receiveFile();
                flag = 1;

                textArea.append("<<SYSTEM>> Transfer Mode -> Chat Mode \n\n");
                receiveMessage();




            }

        }

        void waitingClient() {
            try {
                ss = new ServerSocket();
                ss.bind(new InetSocketAddress(localhost, port));  //binding socket address
                waitBtn.setEnabled(false);
                portField.setEnabled(false);
                cs = ss.accept();  //wait connection from client
                InetSocketAddress socketAddress = (InetSocketAddress) cs.getRemoteSocketAddress();
                connectStateLabel.setText("Connected from Address : " + socketAddress.toString() );  //show message
                jp3.setVisible(true);
                jp4.setVisible(true);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }



        // first part is en/decrypt Text
        String decryptText(String string, Key key, String mode) throws UnsupportedEncodingException {
            Cipher cipher = null;
            byte[] byteText = Base64.getDecoder().decode(string);   // using Base64 encoding for protecting data changed while transmitting
            byte[] decryptedText = new byte[0];
            try {
                cipher = Cipher.getInstance(mode);
                cipher.init(Cipher.DECRYPT_MODE, key);
                decryptedText = cipher.doFinal(byteText);    //code from ppt  derypted with key

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Check if Selected AES key is right. \n\n"); //when use invalid key, show err message
            }

            return new String(decryptedText, "UTF8");  //String - UTF-8
        }

        String encryptText(String string, Key key, String mode) {
            Cipher cipher = null;
            byte[] byteText = string.getBytes();
            byte[] encryptedText = new byte[0];
            try {
                cipher = Cipher.getInstance(mode);
                cipher.init(Cipher.ENCRYPT_MODE, key);
                encryptedText = cipher.doFinal(byteText); //encrypt

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }

            return new String(Base64.getEncoder().encode(encryptedText)); // use Base64 encoding before transferring to protect file changed.
        }



        // en/decrytFile.  from byte[] to byte[] don't use encoding.
        byte[] decryptFile(byte[] file, Key key, String mode) {
            Cipher cipher = null;
            byte[] byteFile = file;
            byte[] decryptedFile = new byte[0];
            try {
                cipher = Cipher.getInstance(mode);
                cipher.init(Cipher.DECRYPT_MODE, key);
                decryptedFile = cipher.doFinal(byteFile);

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Check if Selected AES key is right. \n\n");
            }

            return decryptedFile;
        }

        byte[] encryptFile(byte[] file, Key key, String mode) {
            Cipher cipher = null;
            byte[] byteFile = file;
            byte[] encryptedFile = new byte[0];
            try {
                cipher = Cipher.getInstance(mode);
                cipher.init(Cipher.ENCRYPT_MODE, key);
                encryptedFile = cipher.doFinal(byteFile);

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }
            return encryptedFile;
        }


        void receiveMessage() {

            try {
                in = new DataInputStream(cs.getInputStream());
                textArea.append("<<SYSTEM>> Chat Connected. \n\n");

                while (in != null) {
                    if (flag == 2) {   // flag 2 means, run thread again after first time. then break receiving message for sharing files
                        break;
                    }
                    String msg = in.readUTF();  // use String for transmitting

                    if (msg.equals(WARNINGRSA)) {   // When I get RSA public key I notice with Warning Message
                        String key = in.readUTF();  //So next is key.
                        DefaultTableModel m = (DefaultTableModel) puKeyTable.getModel();
                        m.insertRow(idx - 1, new Object[]{idx, "CLIENT", key});
                        puKeyTable.updateUI();  //Put in Public Key List Table

                        textArea.append("<<SYSTEM>> Receive public RSA key from client. \n");
                        textArea.append("<<SYSTEM>> RSA public key : " + key + "\n\n");

                        idx++;

                    } else if (msg.equals(WARNINGAES)) {  // When I get AES key I notice with Warning Message
                        String key = in.readUTF();
                        String decryptedKey = decryptText(key, prik, "RSA");  // private key is saved when it is generated.
                        //AES key is encrypted with RSA Public key User made before transmitting.
                        aESKeyBox.addItem(decryptedKey);
                        textArea.append("<<SYSTEM>> Receive AES key encrypted with public RSA key from client. \n\n");
                        textArea.append("<<SYSTEM>> AES key(Encrypted) : " + key + "\n\n");
                        textArea.append("<<SYSTEM>> AES key(Decrypted) : " + decryptedKey + "\n\n");
                        //So need to decrypted with own RSA Private Key.

                    } else if (encryptMsgCheck.isSelected()) {  //This is for Encrypt Message Mode, when checkbox is checked,

                        String stringAESKey = aESKeyBox.getSelectedItem().toString(); //load from AES Combobox list. user can select.
                        SecretKeySpec originalKey = new SecretKeySpec(stringAESKey.getBytes("UTF-8"), "AES");
                        //it is saved as String so, making it to Key for decrypting message.

                        String dMsg = decryptText(msg, originalKey, "AES/ECB/PKCS5Padding");

                        textArea.append("Client(Encrypted) : " + msg + "\n");
                        textArea.append("Client(Decrypted) : " + dMsg + "\n");  // show encryted message and decrypted also.

                    } else if (msg.equals("In Transfer Mode. Send File.")) { // This part is for transferring file.
                        textArea.append("Client : " + msg + "\n");  // I use only one socket and one stream I cant share file while transmitting chat.
                        msgField.setEnabled(false);
                        sendFileBtn.setEnabled(true);
                        encryptMsgCheck.setEnabled(false); //so can not use Message part until finish sharing file.
                        receiveFileBtn.setEnabled(false);

                    } else {
                        textArea.append("Client : " + msg + "\n");
                    }
                }


            } catch (IOException e) {
                e.printStackTrace();
            }


        }

        void sendMessage() {

            try {
                if (encryptMsgCheck.isSelected()) { // When endcrypt checkbox is selected, load AES key and endcrypt message.
                    out = new DataOutputStream(cs.getOutputStream());

                    String stringAESKey = aESKeyBox.getSelectedItem().toString();  //load AES key that user selected in Combobox
                    SecretKeySpec originalKey = new SecretKeySpec(stringAESKey.getBytes("UTF-8"), "AES");

                    String t = encryptText(msgField.getText(), originalKey, "AES/ECB/PKCS5Padding");
                    out.writeUTF(t);  //encrypt it and encode before transmit
                } else {
                    out = new DataOutputStream(cs.getOutputStream());
                    out.writeUTF(msgField.getText()); // This is Normal Chatting part, nothing special. just send message in JTextField
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NullPointerException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Check if Selected AES key is right. \n\n"); //when Server and Client select different AES key.
            }
        }

        void generateRSAKey() {
            KeyPairGenerator generator = null;
            try {
                generator = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            pubk = publicKey;
            prik = privateKey;

            puLabel.setText(pubk.getEncoded().toString());
            prLabel.setText(prik.getEncoded().toString());
            //after generating it is entered as Base64 encoding. this is just for knowing whether if I made RSA key or not

            textArea.append("<<SYSTEM>> RSA KEY PAIR GENERATED. \n\n");
            textArea.append("<<SYSTEM>> Public RSA Key : " + new String(Base64.getEncoder().encode(pubk.getEncoded())) + "\n");
            textArea.append("<<SYSTEM>> Private RSA Key : " + new String(Base64.getEncoder().encode(prik.getEncoded())) + "\n\n");
            textScrollPane.getVerticalScrollBar().setValue(textScrollPane.getVerticalScrollBar().getMaximum());
            genRSAKeyBtn.setEnabled(false);
        }

        void generateAESKey() { //Same as RSA key generated part. From material.
            KeyGenerator generator = null;
            try {
                generator = KeyGenerator.getInstance("AES");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            generator.init(128);
            Key key = generator.generateKey();
            byte[] aESKey = key.getEncoded();
            aESKeyBox.addItem(new String(Base64.getEncoder().encode(aESKey)));

            textArea.append("<<SYSTEM>> AES KEY GENERATED. \n\n");
            textArea.append("<<SYSTEM>> AES Key : " + new String(Base64.getEncoder().encode(aESKey)) + "\n\n");
            textScrollPane.getVerticalScrollBar().setValue(textScrollPane.getVerticalScrollBar().getMaximum());
        }

        void sendPuRSAKey() {

            try {
                String puKey = new String(Base64.getEncoder().encode(pubk.getEncoded()));
                out = new DataOutputStream(cs.getOutputStream());
                out.writeUTF(WARNINGRSA);  // I use same stream with Chatting. so before User send Key, they send Warning message to let others know.
                out.writeUTF(puKey);
                textArea.append("<<SYSTEM>> Public RSA key has been sent.\n\n");
                textScrollPane.getVerticalScrollBar().setValue(textScrollPane.getVerticalScrollBar().getMaximum());
            } catch (IOException | NullPointerException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Public RSA key does not exist.\n\n");
            }
        }

        void sendAESKeyEncrypted() {
            Cipher cipher = null;
            try {
                String stringAESKey = aESKeyBox.getSelectedItem().toString();
                textArea.append("<<SYSTEM>> AES Key Selected : " + stringAESKey + "\n\n");
                byte[] byteAESKey = stringAESKey.getBytes();   //First select one AES key.

                cipher = Cipher.getInstance("RSA");
                String stringPuKey = puKeyTable.getValueAt(0, 2).toString(); //And get RSA Public Key from Client/Server.
                byte[] bytePuKey = Base64.getDecoder().decode(stringPuKey);

                PublicKey originalKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytePuKey));
                cipher.init(Cipher.ENCRYPT_MODE, originalKey);

                byte[] encryptedAESKey = cipher.doFinal(byteAESKey);  //  RSA Public((AES key)) ----transmit---->   ))AES key((RSA Private

                textArea.append("<<SYSTEM>> The AES key is encrypted with the RSA public key from the client. \n\n");

                String aESKey = new String(Base64.getEncoder().encode(encryptedAESKey));
                out = new DataOutputStream(cs.getOutputStream());
                out.writeUTF(WARNINGAES); //same as RSA part
                out.writeUTF(aESKey);
                textArea.append("<<SYSTEM>> AES Key has been sent.\n\n");


            } catch (NoSuchAlgorithmException | NoSuchPaddingException | NullPointerException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Check if AES or RSA public Key is right. \n\n");
            } catch (BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Check if AES or RSA public Key is right. \n\n");
            } catch (InvalidKeyException | InvalidKeySpecException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Check if AES or RSA public Key is right. \n\n");
            } catch (IOException e) {
                e.printStackTrace();
            }

            textScrollPane.getVerticalScrollBar().setValue(textScrollPane.getVerticalScrollBar().getMaximum());

        }

        void saveFile(PublicKey pubk, PrivateKey prik) {
            if(!genRSAKeyBtn.isEnabled()) {
                String puFilePath = "c:\\PublicKey.txt";
                String prFilePath = "c:\\PrivateKey.txt";  //every Key is save in C: drive. You might need Administrator authority
                String sPuKey = new String(Base64.getEncoder().encode(pubk.getEncoded()));
                String sPrKey = new String(Base64.getEncoder().encode(prik.getEncoded()));
                try {

                    FileWriter puFileWriter = new FileWriter(puFilePath);  //After generating user can save it to each file.
                    FileWriter prFileWriter = new FileWriter(prFilePath);  //But it is saved as String.txt, it is not safe.
                    puFileWriter.write(sPuKey);
                    prFileWriter.write(sPrKey);
                    puFileWriter.close();
                    prFileWriter.close();
                    textArea.append("<<SYSTEM>> RSA Key pair are saved at C: drive \n\n");
                } catch (IOException e) {
                    e.printStackTrace();
                    textArea.append("<<SYSTEM>> ERR : Need Administrator privileges \n\n");
                }
            } else {
                textArea.append("<<SYSTEM>> ERR : New RSA key does not exist in Server.\n\n");
            }
        }

        void loadFile() {
            try{
                File puFile = new File("C:\\PublicKey.txt");
                File prFile = new File("C:\\PrivateKey.txt");
                String puk = "";
                String prk = "";

                FileReader pufr = new FileReader(puFile);
                FileReader prfr = new FileReader(prFile);
                int cur = 0;
                while((cur = pufr.read()) != -1){
                    puk += (char)cur;
                }
                pufr.close();

                cur = 0;
                System.out.println("\n");
                while((cur = prfr.read()) != -1){
                    prk += (char)cur;
                }
                prfr.close();  //load from C drive and file name must be PublicKey.txt and PrivateKey.txt to load

                Base64.getDecoder().decode(puk);
                Base64.getDecoder().decode(prk);
                // change it to Object Key. Because it is saved as String type.
                pubk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(puk)));
                prik = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(prk)));

                puLabel.setText(pubk.getEncoded().toString());
                prLabel.setText(prik.getEncoded().toString());

                textArea.append("<<SYSTEM>> RSA KEY PAIR LOADED FROM C: DRIVE. \n\n");
                textArea.append("<<SYSTEM>> Public RSA Key : " + new String(Base64.getEncoder().encode(pubk.getEncoded())) + "\n");
                textArea.append("<<SYSTEM>> Private RSA Key : " + new String(Base64.getEncoder().encode(prik.getEncoded())) + "\n\n");

            }catch (FileNotFoundException e) {
                e.getStackTrace();
                textArea.append("<<SYSTEM>> ERR : RSA key does not exist in C: drive.\n\n");
            }catch(IOException e){
                e.getStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }



        // IMPORTANT.   Before sharing file.  the one request receive(Button) first, and the other can send file.
        void receiveFile() {

            byte[] buffer = new byte[1024];
            if (encryptFileCheck.isSelected()) {
                buffer = new byte[1040];    // encrypted length is longer as 16byte so, make it bigger as 16byte.
            }

            File file;
            int length;
            try {
                out = new DataOutputStream(cs.getOutputStream());
                out.writeUTF("In Transfer Mode. Send File.");     //Before start to transfer file, let others know to change stream for sharing.
                textArea.append("<<SYSTEM>> Chat Mode -> Transfer Mode \n\n");
                receiveFileBtn.setEnabled(false); // one request receive file, the other can not request until finish.
                inf = new DataInputStream(cs.getInputStream());

                String fileName = inf.readUTF();
                if(encryptFileCheck.isSelected()) {
                    file = new File(".\\decrypted_" + fileName);
                } else {
                    file = new File(".\\received_" + fileName);
                }
                file.createNewFile();

                long sendingcount = inf.readLong();
                long data = 0;
                fos = new FileOutputStream(file);
                while((length = inf.read(buffer))!= -1) {
                    //  Decrypt Part. After Encrypt and transfer, there is no problem but when try to decrypt, I got error mentioned above.
                    if(encryptFileCheck.isSelected()) {

                        String stringAESKey = aESKeyBox.getSelectedItem().toString();
                        SecretKeySpec originalKey = new SecretKeySpec(stringAESKey.getBytes("UTF-8"), "AES");
                        byte[] dt = decryptFile(buffer, originalKey, "AES/ECB/PKCS5Padding");
                        int llength = inf.readInt();
                        System.out.println(llength);
                        fos.write(dt,0,llength);

                        data += 1;
                        if(data == sendingcount) break;	// end of the file

                    } else {  //normal part.

                        fos.write(buffer,0,length);
                        data += 1;
                        if(data == sendingcount) break;// end of the file
                    }
                }
                if (dSCheck.isSelected()) {  // when user use Digital Signature.
                    String sg = inf.readUTF();  //receive it as String and encode it.
                    String sigData = "Electronic Signature Test";
                    byte[] dSData = sigData.getBytes("UTF8");
                    Signature sig2 = Signature.getInstance("SHA512WithRSA");

                    String stringPuKey = puKeyTable.getValueAt(0, 2).toString(); // Public Key from Other.
                    byte[] bytePuKey = Base64.getDecoder().decode(stringPuKey);
                    PublicKey originalKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytePuKey));

                    sig2.initVerify(originalKey);
                    sig2.update(dSData);

                    textArea.append("<<SYSTEM>> ****** Signature is : " + sig2.verify(Base64.getDecoder().decode(sg)) + " ****** \n");


                }
                fos.close();
                textArea.append("<<SYSTEM>> Received file : " + fileName + " \n");
                receiveFileBtn.setEnabled(true);


            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Filename already exists. \n");

            }
        }

        void sendFile() {
            int length;
            byte[] buffer = new byte[1024];
            File file;
            try {
                outf = new DataOutputStream(cs.getOutputStream());
                outf.writeUTF("Trying to send file. \n");
                int result=jFileChooser.showOpenDialog(null);
                file = new File(jFileChooser.getSelectedFile().toString());  //select file from JFileChooser.
                if(result == JFileChooser.APPROVE_OPTION) {
                    fileField.setText("");
                    if(file.isFile()) {
                        outf.writeUTF(file.getName());
                        fis = new FileInputStream(file);
                        outf.writeLong((file.length()/1024)+1);	// send the number of sending count.
                        while((length = fis.read(buffer))!=-1) {
                            if(encryptFileCheck.isSelected()) {
                                String stringAESKey = aESKeyBox.getSelectedItem().toString();
                                SecretKeySpec originalKey = new SecretKeySpec(stringAESKey.getBytes("UTF-8"), "AES");
                                byte[] t = encryptFile(buffer, originalKey, "AES/ECB/PKCS5Padding");


                                outf.write(t);
                                outf.writeInt(length);  //send each buffer's length for letting receiver know how much data is sending.
                                outf.flush();
                            } else {
                                outf.write(buffer,0,length); //sending only the real data and cut the blank on the buffer
                                outf.flush();
                            }

                        }
                        if (dSCheck.isSelected()){ // send digital signature part
                            String sigData = "Electronic Signature Test";  //Test Signature
                            byte[] dSData = sigData.getBytes("UTF8");
                            Signature sig = Signature.getInstance("SHA512WithRSA");
                            sig.initSign(prik);  //encrypted by my RSA private key.  should send pair Public key to other.
                            sig.update(dSData);
                            byte[] signatureBytes = sig.sign();
                            outf.writeUTF(new String(Base64.getEncoder().encode(signatureBytes)));
                        }
                        fis.close();
                        textArea.append("<<SYSTEM>> Sent file : " + file.getName() + " \n");
                    } else {
                        textArea.append("<<SYSTEM>> ERR : Filename does not exist. \n");
                    }//User can write file name in C drive
                }

            } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
                e.printStackTrace();
                textArea.append("<<SYSTEM>> ERR : Filename does not exist. \n");

            }
        }
    }

    private class ConnectHandler implements ActionListener {  //Connect Handler.
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == waitBtn) {
                try {
                    port = Integer.parseInt(portField.getText());
                    sv.svThread();
                    connectStateLabel.setText("Waiting...");
                } catch (NumberFormatException err) {
                    connectStateLabel.setText("Port missing!!");
                }
            } else if (e.getSource() == msgField) {
                textArea.append("Server : " + msgField.getText() + "\n");
                sv.sendMessage();
                textScrollPane.getVerticalScrollBar().setValue(textScrollPane.getVerticalScrollBar().getMaximum());
                msgField.setText("");
            }
        }
    }

    private class KeyBtnHandler implements ActionListener {  //Every Button. Generate key, Send Key Save and Load key, Send File.
        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == genAESKeyBtn) {
                sv.generateAESKey();

            } else if (e.getSource() == sendAESKeyBtn) {
                sv.sendAESKeyEncrypted();

            } else if (e.getSource() == genRSAKeyBtn) {
                sv.generateRSAKey();

            } else if (e.getSource() == sendPuRSAKeyBtn) {
                sv.sendPuRSAKey();

            } else if (e.getSource() == saveKeyBtn) {
                sv.saveFile(sv.pubk, sv.prik);

            } else if (e.getSource() == loadKeyBtn) {
                sv.loadFile();

            } else if (e.getSource() == receiveFileBtn) {

                sv.flag = 2;
                sv.svThread();

            }else if (e.getSource() == sendFileBtn) {

                sv.sendFile();
                msgField.setEnabled(true);
                encryptMsgCheck.setEnabled(true);
                receiveFileBtn.setEnabled(true);
                sendFileBtn.setEnabled(false);

            }

        }
    }


    //System message for 3 CheckBox Handler.
    private class EncryptMsgHandler implements ItemListener {

        @Override
        public void itemStateChanged(ItemEvent e) {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                textArea.append("<<SYSTEM>> AES En/Decrypted Message Mode\n\n");
            } else {
                textArea.append("<<SYSTEM>> Plain Message Mode\n");
                textArea.append("<<SYSTEM>> Make sure the Client has turned off mode.\n\n");
            }
        }
    }
    private class EncryptFileHandler implements ItemListener {

        @Override
        public void itemStateChanged(ItemEvent e) {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                textArea.append("<<SYSTEM>> AES En/Decrypted File Mode\n\n");
            } else {
                textArea.append("<<SYSTEM>> Plain File Mode\n");
                textArea.append("<<SYSTEM>> Make sure the Client has turned off mode.\n\n");
            }
        }
    }
    private class DSHandler implements ItemListener {
        @Override
        public void itemStateChanged(ItemEvent e) {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                textArea.append("<<SYSTEM>> File Digital Signature Mode\n\n");
            } else {
                textArea.append("<<SYSTEM>> File without Signature Mode\n");
                textArea.append("<<SYSTEM>> Make sure the Client has turned off mode.\n\n");
            }
        }
    }

}



