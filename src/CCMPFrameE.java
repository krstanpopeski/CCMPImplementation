import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;

public class CCMPFrameE {
    private byte[] sourceAddress;
    private byte[] destinationAdress;
    private byte[] pn;
    private byte qos;
    private byte[] encryptedData;
    private byte[] encryptedMic;
    private byte[] nonce;


    public CCMPFrameE(CCMPFrameNE ccmpFrameNE, SecretKey secretKey){
        this.sourceAddress = ccmpFrameNE.getSourceAddress();
        this.destinationAdress = ccmpFrameNE.getDestinationAdress();
        this.pn = ccmpFrameNE.getPn();
        this.nonce = generateNonce();
        this.qos = ccmpFrameNE.getQos();
        this.encryptedData = encrypt(ccmpFrameNE.getData(),secretKey);
        this.encryptedMic = encryptMIC(ccmpFrameNE.getMic(), secretKey);
    }

    public byte [] generateNonce(){
            byte[] nonce = new byte[13];

            System.arraycopy(this.pn, 0, nonce, 0, this.pn.length);
            int counter = 0;
            for(int i=this.pn.length;i<this.sourceAddress.length+this.pn.length;i++){
                nonce[i] = this.sourceAddress[counter];
                counter++;
            }
            nonce[this.pn.length+this.sourceAddress.length] = qos;

            return nonce;


    }



    private byte [] encrypt(byte [] plainText, SecretKey secretKey){
        System.out.println("Encrypting the data...");
        byte [] counter = new byte[3];
        counter[2] = (byte) 1;
        byte [] nonceCounter = new byte[16];
        ByteBuffer target = ByteBuffer.wrap(nonceCounter);
        target.put(nonce).put(counter);

        byte [] block = new byte[16];


        int read = 0;

        byte [] encryptedData = new byte[plainText.length];
        byte [] xored;

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            for(int i=0;i<(plainText.length/16);i++){
                int count = 0;
                for(int j=read;j<read+16;j++){
                    block[count] = plainText[j];
                    count++;
                }


                byte [] temp = cipher.update(nonceCounter);
                xored = XOR(temp,block);
                count = 0;
                for(int j = read;j<read+16;j++){
                    encryptedData[j] = xored[count++];
                }
                read+=16;
                nonceCounter[15]++;

            }

            int count = 0;

            for(int i=0;i<block.length;i++){
                block[i] = (byte) 0;
            }

            for(int i=read;i<plainText.length;i++){
                block[count++] = plainText[i];
            }


            byte [] temp = cipher.doFinal(nonceCounter);
            xored = XOR(temp,block);
            count = 0;


            for(int i=read;i<plainText.length;i++){
                encryptedData[i] = xored[count++];
            }


        }
        catch(Exception e){
            System.out.println(e.getMessage());
        }

        System.out.println("Successfully encrypted!");
        return encryptedData;


    }

    public byte [] XOR(byte [] array1, byte [] array2){
        byte [] result = new byte[16];
        byte [] array1_2 = new byte[16];
        byte [] array2_2 = new byte[16];

        System.arraycopy(array1, 0, array1_2, 0, array1.length);
        System.arraycopy(array2, 0, array2_2, 0, array2.length);

        for(int i=0;i<16;i++){
            result[i] = (byte)(array1_2[i] ^ array2_2[i]);
        }

        return result;
    }

    private byte[] encryptMIC(byte [] mic, SecretKey secretKey){
        System.out.println("Encrypting the MIC...");
        byte [] nonceCounter = new byte [16];
        byte [] counter = new byte[3];

        ByteBuffer target = ByteBuffer.wrap(nonceCounter);
        target.put(nonce).put(counter);



        byte [] temp = new byte[mic.length];
        byte [] encryptedMIC = new byte[8];
        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            temp = cipher.doFinal(nonceCounter);
            byte [] temp2 = XOR(temp,mic);
            System.arraycopy(temp2, 0, encryptedMIC, 0, 8);
        }
        catch (Exception e){
            System.out.println(e.getMessage());
        }

        System.out.println("MIC successfully encrypted!");
        return encryptedMIC;

    }

    public byte[] getDestinationAdress() {
        return destinationAdress;
    }

    public byte[] getSourceAddress() {
        return sourceAddress;
    }

    public byte[] getPn() {
        return pn;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getEncryptedMic() {
        return encryptedMic;
    }

    public byte getQos() {
        return qos;
    }
}
