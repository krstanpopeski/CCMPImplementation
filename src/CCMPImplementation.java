import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class CCMPImplementation {

    public static void main(String[] args) {

        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(128);
            SecretKey secretKey = gen.generateKey();

            byte [] data = "Test data for testing the CCMP protocol.".getBytes(StandardCharsets.UTF_8);
            byte [] pn = "000001".getBytes(StandardCharsets.UTF_8);
            byte qos = (byte) 1;


            Sender sender = new Sender("6A:F3:EB:D5:AC:89","5C:F2:4B:95:49:29",data,pn,qos,secretKey);
            Reciever reciever = new Reciever(secretKey);

            sender.Send(reciever);
        }
        catch(Exception e){
            System.out.println(e.getMessage());
        }


    }
}