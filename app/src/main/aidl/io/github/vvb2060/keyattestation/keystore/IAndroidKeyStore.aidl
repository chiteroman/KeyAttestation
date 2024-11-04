package io.github.vvb2060.keyattestation.keystore;

interface IAndroidKeyStore {
    byte[] getCertificateChain(String alias);
    boolean containsAlias(String alias);
    void deleteAllEntry();
    byte[] generateKeyPair(String alias, String attestKeyAlias, boolean useStrongBox,
                           boolean includeProps, boolean uniqueIdIncluded, int idFlags);
    byte[] attestDeviceIds(int idFlags);
}
