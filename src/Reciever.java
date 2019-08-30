import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;

public class Reciever {

    private CCMPFrameE ccmpFrameE;
    private CCMPFrameNE ccmpFrameNE;
    private SecretKey secretKey;

    public Reciever(SecretKey secretKey){
        this.ccmpFrameE = null;
        this.ccmpFrameNE = null;
        this.secretKey = secretKey;
    }

    public void recieve(CCMPFrameE ccmpFrameE){
        System.out.println("Receiving ...");
        this.ccmpFrameE = ccmpFrameE;
        ccmpFrameNE = decrypt(ccmpFrameE);
    }


    private byte [] decryptM(CCMPFrameE ccmpFrameE){
        System.out.println("Decrypting MIC ...");
        byte [] encryptedMIC = ccmpFrameE.getEncryptedMic();
        byte [] mic = new byte[encryptedMIC.length];
        byte [] nonceCounter = new byte [16];
        byte [] counter = new byte[3];

        ByteBuffer target = ByteBuffer.wrap(nonceCounter);
        target.put(ccmpFrameE.getNonce()).put(counter);



        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            byte [] temp = cipher.doFinal(nonceCounter);
            mic = XOR(temp,encryptedMIC);
        }
        catch(Exception e){
            System.out.println(e.getMessage());
        }
        System.out.println("MIC Successfully decrypted ...");
        return mic;
    }



    private CCMPFrameNE decrypt(CCMPFrameE ccmpFrameE){
        System.out.println("Decrypting data ...");
        byte[] nonce = ccmpFrameE.getNonce();
        byte [] counter = new byte[3];

        counter[2] = (byte) 1;

        byte [] nonceCounter = new byte[16];
        byte [] data = new byte[ccmpFrameE.getEncryptedData().length];


        ByteBuffer buffer = ByteBuffer.wrap(nonceCounter);
        buffer.put(nonce).put(counter);

        byte [] encryptedData = ccmpFrameE.getEncryptedData();
        byte [] block = new byte[16];


        int count = 0;
        int read = 0;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);

            for(int i=0;i<(encryptedData.length/16);i++){
                count = 0;
                for(int j=read;j<read+16;j++){
                    block[count++] = encryptedData[read];
                }



                byte [] temp = cipher.update(nonceCounter);
                byte [] xored = XOR(temp,block);
                count=0;
                for(int j=read;j<read+16;j++){
                    data[j] = xored[count++];
                }
                nonceCounter[15]++;
                read+=16;

            }


            for(int i=0;i<16;i++){
                block[i] = (byte) 0;
            }

            count=0;
            for(int i=read;i<encryptedData.length;i++){
                block[count++] = encryptedData[i];
            }

            byte [] temp = cipher.doFinal(nonceCounter);
            byte [] xored = XOR(temp,block);

            count = 0;
            for(int i=read;i<encryptedData.length;i++){
                data[i] = xored[count++];
            }

        }
        catch (Exception e){
            System.out.println(e.getMessage());
        }

        CCMPFrameNE ccmpFrameNE = new CCMPFrameNE(ccmpFrameE.getSourceAddress(),ccmpFrameE.getDestinationAdress(),data,ccmpFrameE.getPn(),ccmpFrameE.getQos(),secretKey);

        byte [] decryptedMic = decryptM(ccmpFrameE);
        byte [] mic = ccmpFrameNE.getMic();

        boolean same = true;
        if(decryptedMic.length == mic.length){
            for(int i=0;i<decryptedMic.length;i++){
                if(decryptedMic[i] != mic[i]){
                    same = false;
                    break;
                }

            }
        }

        if(!same){
            System.err.println("Integrity check failed!");
            System.err.println("Packet dropped!");
            return null;
        }
        else{
            System.out.println("Successfully decrypted!");
            System.out.println("Integrity check successfully!");

            return ccmpFrameNE;
        }


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
}
