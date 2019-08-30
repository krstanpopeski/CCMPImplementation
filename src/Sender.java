import javax.crypto.SecretKey;

public class Sender {

    CCMPFrameNE ccmpFrameNE;
    CCMPFrameE ccmpFrameE;
    SecretKey secretKey;

    public Sender(String sourceAddress, String destinationAddress, byte [] data, byte [] pn, byte qos, SecretKey secretKey){
        ccmpFrameNE = new CCMPFrameNE(sourceAddress, destinationAddress, data, pn, qos,secretKey);
        ccmpFrameE = new CCMPFrameE(ccmpFrameNE,secretKey);
        this.secretKey = secretKey;
    }

    public void Send(Reciever reciever){
        System.out.println("Sending ...");
        reciever.recieve(this.ccmpFrameE);
    }


}
