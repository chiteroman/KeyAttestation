package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;

import androidx.annotation.NonNull;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import io.github.vvb2060.keyattestation.AppApplication;

public class CustomX509Certificate extends X509Certificate {
    private final X509Certificate x509Certificate;
    private final boolean secretMode = AppApplication.app.getSharedPreferences("settings", Context.MODE_PRIVATE).getBoolean("secret_mode", true);

    public CustomX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        x509Certificate.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        x509Certificate.checkValidity(date);
    }

    @Override
    public int getVersion() {
        return x509Certificate.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return x509Certificate.getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return x509Certificate.getIssuerDN();
    }

    @Override
    public Principal getSubjectDN() {
        return secretMode ? new X500Principal("SERIALNUMBER=HIDDEN,T=TEE") : x509Certificate.getSubjectDN();
    }

    @Override
    public Date getNotBefore() {
        return secretMode ? new Date(0) : x509Certificate.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return secretMode ? new Date() : x509Certificate.getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return x509Certificate.getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        return x509Certificate.getSignature();
    }

    @Override
    public String getSigAlgName() {
        return x509Certificate.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return x509Certificate.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return x509Certificate.getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return x509Certificate.getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return x509Certificate.getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return x509Certificate.getKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        return x509Certificate.getBasicConstraints();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return x509Certificate.getEncoded();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        x509Certificate.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        x509Certificate.verify(key, sigProvider);
    }

    @NonNull
    @Override
    public String toString() {
        return x509Certificate.toString();
    }

    @Override
    public PublicKey getPublicKey() {
        return x509Certificate.getPublicKey();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return x509Certificate.hasUnsupportedCriticalExtension();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return x509Certificate.getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return x509Certificate.getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return x509Certificate.getExtensionValue(oid);
    }
}
