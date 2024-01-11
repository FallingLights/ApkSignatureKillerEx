package bin.mt.test;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Application;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.widget.TextView;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public class MainActivity extends Activity {

    public static class App extends Application {
        static {
            new bin.mt.signature.KillerApplication(); //Comment out this line to disable countersigning
        }
    }

    static {
        System.loadLibrary("test");
    }

    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView msg = findViewById(R.id.msg);

        // The following demonstrates three ways to get the MD5 of a signature

        String signatureExpected = "3bf8931788824c6a1f2c6f6ff80f6b21";
        String signatureFromAPI = md5(signatureFromAPI());
        String signatureFromAPK = md5(signatureFromAPK());
        String signatureFromSVC = md5(signatureFromSVC());

        // When over-signing is turned on, the API and APK methods will get the false signature MD5

        // And the SVC method always gets the real signature MD5

        SpannableStringBuilder sb = new SpannableStringBuilder();
        append(sb, "Expected: ", signatureExpected, Color.BLACK);
        append(sb, "From API: ", signatureFromAPI, signatureExpected.equals(signatureFromAPI) ? Color.BLUE : Color.RED);
        append(sb, "From APK: ", signatureFromAPK, signatureExpected.equals(signatureFromAPK) ? Color.BLUE : Color.RED);
        append(sb, "From SVC: ", signatureFromSVC, signatureExpected.equals(signatureFromSVC) ? Color.BLUE : Color.RED);
        // Of course, SVC is not absolutely safe, but relatively more reliable,
        // the actual use of the means need to be combined with more
        append(sb, "Package Name: ", getAPKPackageName(), Color.BLACK);

        msg.setText(sb);
    }

    /**
     * Appends a header and value pair to a SpannableStringBuilder, applying a specified color to the text.
     *
     * This method begins by recording the current length of the SpannableStringBuilder `sb`, which
     * marks the start point of the new text to be appended. It then appends the `header`, `value`, and
     * a newline character to `sb`. After appending, it calculates the new length of `sb`, marking the
     * end point of the appended text.
     *
     * A ForegroundColorSpan, with the specified `color`, is then applied to the text range from the
     * recorded start point to the end point. This span sets the text color of the appended header and
     * value. The span is exclusive-exclusive, meaning it applies to characters at the start index and
     * up to, but not including, characters at the end index.
     *
     * @param sb The SpannableStringBuilder to which the text and color span are appended.
     * @param header The header text to append.
     * @param value The value text to append.
     * @param color The color to apply to the appended text.
     */
    private static void append(SpannableStringBuilder sb, String header, String value, int color) {
        int start = sb.length();
        sb.append(header).append(value).append("\n");
        int end = sb.length();
        sb.setSpan(new ForegroundColorSpan(color), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    /**
     * Get the signature of the current application from the API
     * @return byte[] - Encoded digital signature of the APK, or null if extraction is unsuccessful.
     */
    private byte[] signatureFromAPI() {
        try {
            @SuppressLint("PackageManagerGetSignatures")
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
            return info.signatures[0].toByteArray();
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Extracts the digital signature from the application's APK file as an encoded byte array.
     *
     * Utilizes a ZipFile to search the META-INF directory of the APK for signature files
     * with RSA, DSA, or EC extensions. Upon finding a relevant file, it processes it to
     * generate an X509Certificate and extracts its encoded form.
     *
     * The function returns null if it fails to find a signature file or encounters errors
     * during processing. Exception details are logged.
     *
     * @return byte[] - Encoded digital signature of the APK, or null if extraction is unsuccessful.
     */
    private byte[] signatureFromAPK() {
        try (ZipFile zipFile = new ZipFile(getPackageResourcePath())) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                    InputStream is = zipFile.getInputStream(entry);
                    CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                    X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(is);
                    return x509Cert.getEncoded();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Extracts the digital signature from the application's SVC (service) file as an encoded byte array.
     *
     * This function opens the SVC file using `ParcelFileDescriptor.adoptFd` and then reads it
     * as a ZipInputStream. It iterates through the zip entries to locate signature files within the
     * META-INF directory, identifiable by their RSA, DSA, or EC extensions. Upon finding a matching
     * file, the function uses a CertificateFactory to create an X509Certificate and then extracts
     * its encoded form as the digital signature.
     *
     * In case of failure to find a signature file or if any exceptions occur during processing,
     * the function logs the error details and returns null.
     *
     * @return byte[] - Encoded digital signature of the SVC file, or null if unsuccessful in extraction.
     */
    private byte[] signatureFromSVC() {
        try (ParcelFileDescriptor fd = ParcelFileDescriptor.adoptFd(openAt(getPackageResourcePath()));
             ZipInputStream zis = new ZipInputStream(new FileInputStream(fd.getFileDescriptor()))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().matches("(META-INF/.*)\\.(RSA|DSA|EC)")) {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                    X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(zis);
                    return x509Cert.getEncoded();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String getAPKPackageName() {
        return getApplicationContext().getPackageName();
    }

    /**
     * Computes the MD5 hash of a given byte array and returns its hexadecimal string representation.
     *
     * This function first checks if the input byte array is null, returning the string "null" in that case.
     * If the input is valid, it calculates the MD5 hash using Java's MessageDigest class. The resulting
     * hash, a byte array, is then converted into a hexadecimal string. This conversion involves mapping
     * each byte of the hash to two hexadecimal characters, using a predefined string of hex digits
     * ("0123456789abcdef"). The function concatenates these characters to form the final MD5 hash string.
     *
     * If the MD5 hashing algorithm is not available in the environment (indicated by a
     * NoSuchAlgorithmException), the function throws a RuntimeException encapsulating the original exception.
     *
     * @param bytes The byte array to hash.
     * @return String - The hexadecimal string representation of the MD5 hash, or "null" if the input is null.
     * @throws RuntimeException If the MD5 hashing algorithm is not available.
     */
    private String md5(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        try {
            byte[] digest = MessageDigest.getInstance("MD5").digest(bytes);
            String hexDigits = "0123456789abcdef";
            char[] str = new char[digest.length * 2];
            int k = 0;
            for (byte b : digest) {
                str[k++] = hexDigits.charAt(b >>> 4 & 0xf);
                str[k++] = hexDigits.charAt(b & 0xf);
            }
            return new String(str);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static native int openAt(String path);

}