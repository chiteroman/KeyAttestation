package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

import androidx.annotation.NonNull;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason) {
    private static JSONObject json = new JSONObject();

    static {
        if (isConnectedToInternet()) {
            try {
                json = loadFromUrl();
            } catch (Throwable t) {
                Log.e(AppApplication.TAG, "RevocationList", t);
                try {
                    json = loadFromRaw();
                } catch (Throwable th) {
                    Log.e(AppApplication.TAG, "RevocationList", th);
                }
            }
        } else {
            try {
                json = loadFromRaw();
            } catch (Throwable t) {
                Log.e(AppApplication.TAG, "RevocationList", t);
            }
        }
    }

    private static boolean isConnectedToInternet() {
        ConnectivityManager connectivityManager = (ConnectivityManager) AppApplication.app.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            NetworkInfo activeNetwork = connectivityManager.getActiveNetworkInfo();
            return activeNetwork != null && activeNetwork.isConnected();
        }
        return false;
    }

    private static JSONObject loadFromUrl() throws Throwable {
        URL url = new URL("https://android.googleapis.com/attestation/status");

        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setDefaultUseCaches(false);
        con.setUseCaches(false);

        con.setRequestMethod("GET");

        con.setRequestProperty("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate");
        con.setRequestProperty("Pragma", "no-cache");
        con.setRequestProperty("Expires", "0");

        StringBuilder response = new StringBuilder();

        String line;
        try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            while ((line = in.readLine()) != null) {
                response.append(line);
            }
        }

        con.disconnect();

        Log.i(AppApplication.TAG, "Got json from internet");

        return new JSONObject(response.toString());
    }

    private static JSONObject loadFromRaw() throws Throwable {
        StringBuilder stringBuilder = new StringBuilder();

        String line;
        try (BufferedReader in = new BufferedReader(new InputStreamReader(AppApplication.app.getResources().openRawResource(R.raw.status)))) {
            while ((line = in.readLine()) != null) {
                stringBuilder.append(line);
            }
        }

        Log.i(AppApplication.TAG, "Got json from local");

        return new JSONObject(stringBuilder.toString());
    }

    public static RevocationList get(BigInteger serialNumber) {
        String serialNumberString = serialNumber.toString(16).toLowerCase();

        try {
            JSONObject entries = json.getJSONObject("entries");

            JSONObject revoke = entries.getJSONObject(serialNumberString);

            return new RevocationList(revoke.getString("status"), revoke.getString("reason"));

        } catch (Throwable t) {
            Log.i(AppApplication.TAG, "Couldn't find " + serialNumberString + " in json");
        }

        return null;
    }

    @NonNull
    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
