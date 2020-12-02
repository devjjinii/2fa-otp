import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

public class GoogleOTP {
    public static void main(String[] args) {
        GoogleOTP otp = new GoogleOTP();
        HashMap<String, String> map = otp.generate("username", "host");
        String otpkey = map.get("encodedKey");
        String url = map.get("url");
        System.out.println(otpkey);
        System.out.println(url);

        // 아래의 결과는 당연히 false
        // boolean check = otp.checkCode("OTP번호", otpkey);

        // 테스트 
        Scanner scan = new Scanner(System.in);
        boolean check = otp.checkCode(scan.next(), otpkey);
        System.out.println(check);

        check = otp.checkCode(scan.next(), otpkey);
        System.out.println(check);
    }

    // QR 코드에 쓸 키와 url 과 secretKey 생성
    public HashMap<String, String> generate(String userName, String hostName) {
        HashMap<String, String> map = new HashMap<String, String>();
        byte[] buffer = new byte[5 + 5 * 5];
        new Random().nextBytes(buffer);
        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 10);
        byte[] bEncodedKey = codec.encode(secretKey);

        String encodedKey = new String(bEncodedKey);
        // 프로퍼티로 뺄 Key 직접 지정 가능
        String propertyKey = "it2elp4AAaskzdf3";
        String madeKey = propertyKey.replace(" ", "").toUpperCase();

        String url = getQRBarcodeURL(userName, hostName, madeKey);
        // Google OTP 앱에 userName@hostName 으로 저장됨
        // key를 입력하거나 생성된 QR코드를 바코드 스캔하여 등록

        map.put("encodedKey", madeKey);
        map.put("url", url);
        return map;
    }

    // 입력한 OTP 코드와 생성된 secretKey 를 비교
    public boolean checkCode(String userCode, String otpkey) {
        long otpnum = Integer.parseInt(userCode); // Google OTP 앱에 표시되는 6자리 숫자
        long wave = new Date().getTime() / 30000; // Google OTP의 주기는 30초
        boolean result = false;
        try {
            Base32 codec = new Base32();
            byte[] decodedKey = codec.decode(otpkey);
            int window = 3;
            for (int i = -window; i <= window; ++i) {
                long hash = verifyCode(decodedKey, wave + i);
                if (hash == otpnum) result = true;
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }

    private static int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[20 - 1] & 0xF;

        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        return (int) truncatedHash;
    }

    public static String getQRBarcodeURL(String user, String host, String secret) {
        // QR코드 주소 생성
        //String format2 = "http://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";
        //return String.format(format2, user, host, secret);
        try {
            return "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/"
                    + URLEncoder.encode(user + "@" + host, "UTF-8").replace("+", "%20")
                    + "?secret=" + URLEncoder.encode(secret, "UTF-8").replace("+", "%20");

        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
