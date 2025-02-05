package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason) {
    private static final JSONObject data = getStatus();

    private static String toString(InputStream input) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } else {
            var output = new ByteArrayOutputStream(8192);
            var buffer = new byte[8192];
            for (int length; (length = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, length);
            }
            return output.toString();
        }
    }

    private static JSONObject getStatus() {
        if (isConnectedToInternet()) {
            HttpURLConnection connection = null;
            try {
                connection = getHttpURLConnection();

                if (connection == null)
                    throw new Exception();

                String str = toString(connection.getInputStream());

                return new JSONObject(str);

            } catch (Throwable t) {
                Log.e(AppApplication.TAG, "getStatus [remote]", t);
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }

        try (InputStream inputStream = AppApplication.app.getResources().openRawResource(R.raw.status)) {
            return new JSONObject(toString(inputStream));
        } catch (Throwable t) {
            Log.e(AppApplication.TAG, "getStatus [local]", t);
        }

        return new JSONObject();
    }

    public static RevocationList get(BigInteger serialNumber) {
        String serialNumberString = serialNumber.toString(16).toLowerCase();
        try {
            JSONObject entries = data.getJSONObject("entries");
            JSONObject revocationEntry = entries.optJSONObject(serialNumberString);

            if (revocationEntry == null)
                return null;

            return new RevocationList(
                    revocationEntry.getString("status"),
                    revocationEntry.getString("reason")
            );
        } catch (JSONException e) {
            Log.e(AppApplication.TAG, "Error parsing JSON entries", e);
        }
        return null;
    }

    private static HttpURLConnection getHttpURLConnection() {
        try {
            URL url = new URL("https://android.googleapis.com/attestation/status");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            connection.setUseCaches(false);
            connection.setDefaultUseCaches(false);

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate");
            connection.setRequestProperty("Pragma", "no-cache");
            connection.setRequestProperty("Expires", "0");

            return connection;
        } catch (Throwable t) {
            Log.e(AppApplication.TAG, "getHttpURLConnection", t);
        }
        return null;
    }

    private static boolean isConnectedToInternet() {
        ConnectivityManager connectivityManager = (ConnectivityManager) AppApplication.app.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) return false;

        Network network = connectivityManager.getActiveNetwork();
        if (network == null) return false;

        NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
        return capabilities != null &&
                (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));
    }

    @NonNull
    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
