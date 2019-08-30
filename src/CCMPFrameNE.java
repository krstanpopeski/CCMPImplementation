import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.sql.SQLOutput;
import java.util.List;

public class CCMPFrameNE {

    private byte[] sourceAddress;
    private byte[] destinationAdress;
    private byte qos;
    private byte[] pn;
    private byte[] data;
    private byte[] mic;

    public CCMPFrameNE(String sourceAddress, String destinationAddress, byte[] data, byte[] pn, byte qos, SecretKey secretKey ){
        this.sourceAddress = parseMacAddress(sourceAddress);
        this.destinationAdress = parseMacAddress(destinationAddress);
        this.pn = new byte[6];
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, this.data.length);
        System.arraycopy(pn,0,this.pn,0,this.pn.length);
        this.pn[this.pn.length-1] =  this.pn[this.pn.length-1] ++;
        this.qos = qos;
        this.mic = generateMIC(secretKey);
    }

    public CCMPFrameNE(byte [] sourceAddress, byte [] destinationAddress, byte[] data, byte[] pn, byte qos,SecretKey secretKey ){
        this.sourceAddress = sourceAddress;
        this.destinationAdress = destinationAddress;
        this.pn = new byte[6];
        this.data = new byte[data.length];
        System.arraycopy(data, 0, this.data, 0, this.data.length);
        System.arraycopy(pn,0,this.pn,0,this.pn.length);
        this.pn[this.pn.length-1] =  this.pn[this.pn.length-1] ++;
        this.qos = qos;
        this.mic = generateMIC(secretKey);
    }


    private byte[] parseMacAddress(String macAdress){
        String[] bytes = macAdress.split(":");
        byte [] parsed = new byte[bytes.length];

        for (int x =0; x < bytes.length; x++){
            BigInteger temp = new BigInteger(bytes[x], 16);
            byte[] raw = temp.toByteArray();
            parsed[x] = raw[raw.length -1];

        }

        return parsed;
    }


    public byte[] generateNonce(){
        System.out.println("Generating the nonce...");
        byte[] nonce = new byte[16];

        System.arraycopy(this.pn, 0, nonce, 0, this.pn.length);
        int counter = 0;
        for(int i=this.pn.length;i<this.sourceAddress.length+this.pn.length;i++){
            nonce[i] = this.sourceAddress[counter];
            counter++;
        }
        nonce[this.pn.length+this.sourceAddress.length] = qos;
        for(int i=this.pn.length+this.sourceAddress.length+1;i<16;i++){
            nonce[i] = 0;
        }

        System.out.println("Nonce generated!");
        return nonce;


    }


    private byte[] generateMIC(SecretKey secretKey){
        System.out.println("Generating the MIC...");
        byte [] input = new byte[destinationAdress.length + sourceAddress.length + pn.length + data.length];
        ByteBuffer target = ByteBuffer.wrap(input);
        target.put(destinationAdress);
        target.put(sourceAddress);
        target.put(qos);
        target.put(data);

        byte [] block = new byte[16];

        byte [] nonce = generateNonce();


        for(int i=0;i<16;i++){
            block[i] = input[i];
        }


        byte [] xored = XOR(block,nonce);

        byte [] mic = new byte[8];

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
            byte [] ciphertextBlock = cipher.update(xored);
            int read = 16;
            for(int i=0;i<(((input.length )  / 16) - 1);i++){
                int counter = 0;
                for(int j=read;j<read+16;j++){
                    block[counter++] = input[j];

                }
                read+=16;
                xored = XOR(block,ciphertextBlock);
                ciphertextBlock = cipher.update(xored);


            }

            for(int i=0;i<16;i++){
                block[i] = (byte) 0;
            }


            int counter = 0;
            for(int i=read;i<input.length;i++){
                block[counter++] = input[i];
            }

            xored = XOR(block,ciphertextBlock);
            ciphertextBlock = cipher.doFinal(xored);

            for(int i=0;i<ciphertextBlock.length-8;i++){
                mic[i] = ciphertextBlock[i];
            }


        }
        catch (Exception e){
            System.out.println("Exception in the NE Generate MIC");
            System.out.println(e.getMessage());
        }

        System.out.println("MIC generated!");
        return mic;

    }

    public byte [] XOR(byte [] array1, byte [] array2){
        byte [] result = new byte[16];
        for(int i=0;i<16;i++){
            result[i] = (byte)(array1[i] ^ array2[i]);
        }

        return result;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getPn() {
        return pn;
    }

    public byte[] getSourceAddress() {
        return sourceAddress;
    }

    public byte[] getDestinationAdress() {
        return destinationAdress;
    }

    public byte[] getMic() {
        return mic;
    }

    public byte getQos() {
        return qos;
    }
}
