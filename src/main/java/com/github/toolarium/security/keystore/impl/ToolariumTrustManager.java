/*
 * ToolariumTrustManager.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.keystore.impl;

import com.github.toolarium.common.stacktrace.StackTrace;
import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.impl.CertificateVerifier;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.AlgorithmConstraints;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Toolariun {@link TrustManager} which logs the verification.
 *  
 * @author patrick
 */
public class ToolariumTrustManager extends X509ExtendedTrustManager {
    private static final Logger LOG = LoggerFactory.getLogger(ToolariumTrustManager.class);
    private static final int CERT_NOT_CHECKED = 0;
    private static final int CERT_CHECKFAILED = 1;
    private static final int CERT_INVALIDSIGNATURE = 2;
    private static final int CERT_CERTEXPIRED = 3;
    private static final int CERT_CAEXPIRED = 4;
    private static final int CERT_UNKNOWNCA = 5;
    private static final int CERT_INVALIDCOMMONNAME = 6;
    private static final int CERT_OK = 7;
    private static final Integer SAN_TYPE_DNS = Integer.valueOf(2);
    private static final Integer SAN_TYPE_IP = Integer.valueOf(7);
    private static final Pattern IPV4_PATTERN = Pattern.compile("(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");
    private static final Pattern IPV6_PATTERN = Pattern.compile("[0-9a-fA-F:.]+(%[0-9a-zA-Z._-]+)?");

    private final Set<X509Certificate> trustedCerts;
    private final ThreadLocal<Integer> certCheckResult;
    private final CertificateVerifier certificateVerifier;
    private final AtomicBoolean missingHostnameWarningLogged;
    private volatile boolean verifyCertificate;
    private volatile boolean issuerRequired;
    private volatile String hostname;


    /**
     * Constructor for ToolariumTrustManager. No host name is set, so host name verification
     * is skipped unless {@link #setHostname(String)} is called or {@link #getHostname()} is overridden.
     */
    public ToolariumTrustManager() {
        this(null);
    }


    /**
     * Constructor for ToolariumTrustManager
     *
     * @param hostname the expected server host name used for host name verification, or {@code null} to skip it
     */
    public ToolariumTrustManager(String hostname) {
        // every certificate is stored on its own (X509Certificate equals compares the encoded certificate)
        trustedCerts = ConcurrentHashMap.newKeySet();
        certCheckResult = ThreadLocal.withInitial(() -> CERT_NOT_CHECKED);
        // own instance, so that changing the revocation setting does not affect other users of the shared verifier
        certificateVerifier = new CertificateVerifier();
        certificateVerifier.setTrustedCertificates(new ArrayList<X509Certificate>());
        missingHostnameWarningLogged = new AtomicBoolean(false);
        verifyCertificate = true;
        issuerRequired = false;
        this.hostname = hostname;
    }


    /**
     * Adds a trusted certificate
     * 
     * @param cert the certificate to trust
     */
    public void addTrustedCertificate(X509Certificate cert) {
        if (cert == null) {
            return;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding trust certificate: {}", cert.getIssuerX500Principal());
        }

        synchronized (trustedCerts) {
            // the trust list of the verifier is only rebuilt if the certificate is new
            if (!trustedCerts.contains(cert)) {
                // first the verifier gets the new trust list, then the certificate is published in the trusted
                // certificates: a concurrent check never sees a certificate which the verifier does not trust yet
                List<X509Certificate> newTrustList = new ArrayList<>(trustedCerts);
                newTrustList.add(cert);
                certificateVerifier.setTrustedCertificates(newTrustList);
                trustedCerts.add(cert);
            }
        }
    }
    

    /**
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String protocol) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Client certificate chain is empty!");
        }

        // the host name belongs to the server: it is not verified for client certificates
        verifyCertificateChain(chain, protocol, null, false);
    }


    /**
     * @see javax.net.ssl.X509ExtendedTrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String, java.net.Socket)
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String protocol, Socket socket) throws CertificateException {
        checkClientTrusted(chain, protocol);
        checkAlgorithmConstraints(chain, getAlgorithmConstraints(socket));
    }


    /**
     * @see javax.net.ssl.X509ExtendedTrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String, javax.net.ssl.SSLEngine)
     */
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String protocol, SSLEngine engine) throws CertificateException {
        checkClientTrusted(chain, protocol);
        checkAlgorithmConstraints(chain, getAlgorithmConstraints(engine));
    }


    /**
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String protocol) throws CertificateException {
        checkServerTrusted(chain, protocol, getHostname());
    }


    /**
     * @see javax.net.ssl.X509ExtendedTrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String, java.net.Socket)
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String protocol, Socket socket) throws CertificateException {
        // a configured host name wins, otherwise the peer host of this connection is verified
        checkServerTrusted(chain, protocol, selectHostname(getPeerHost(socket)));
        checkAlgorithmConstraints(chain, getAlgorithmConstraints(socket));
    }


    /**
     * @see javax.net.ssl.X509ExtendedTrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String, javax.net.ssl.SSLEngine)
     */
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String protocol, SSLEngine engine) throws CertificateException {
        // a configured host name wins, otherwise the peer host of this connection is verified
        checkServerTrusted(chain, protocol, selectHostname(getPeerHost(engine)));
        checkAlgorithmConstraints(chain, getAlgorithmConstraints(engine));
    }


    /**
     * Checks the server certificate chain against the given host name.
     *
     * @param chain the certificate chain
     * @param protocol the protocol
     * @param server the expected server host name of this check, or {@code null} to skip the host name verification
     * @throws CertificateException in case of error
     */
    private void checkServerTrusted(X509Certificate[] chain, String protocol, String server) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Server certificate chain is empty!");
        }

        if (LOG.isDebugEnabled()) {
            for (int i = 0; i < chain.length; i++) {
                LOG.debug("Server certificate #{}: \n{}", i + 1, CertificateUtilFactory.getInstance().getConverter().formatPKCS7(chain[i]));
            }
        }

        if (verifyCertificate) {
            verifyCertificateChain(chain, protocol, server, true);

            // Only add certificates after successful verification so that a cert that fails
            // verification is not left in the trust store for subsequent connection attempts.
            // Without verification nothing is added, otherwise the certificates would still be
            // trusted after the verification is enabled again.
            for (int i = 0; i < chain.length; i++) {
                if (trustServerCertificate(chain[i])) {
                    addTrustedCertificate(chain[i]);
                }
            }
        }
    }

    
    /**
     * Set the verify certificate
     *
     * @param verifyCertificate true to verify certificates
     */
    public void setVerifyCertificate(boolean verifyCertificate) {
        this.verifyCertificate = verifyCertificate;
    }


    /**
     * Set the expected server host name used for host name verification.
     *
     * @param hostname the host name, or {@code null} to skip host name verification
     */
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }


    /**
     * Defines if the issuer of every CA certificate of the chain must be in the trusted certificates. The validity
     * of a trusted issuer is always checked. If the issuer is not trusted, the certificate is rejected as unknown CA
     * if true (default false: the issuer check is skipped).
     *
     * @param issuerRequired true to reject a chain if the issuer of a CA certificate is not trusted
     */
    public void setIssuerRequired(boolean issuerRequired) {
        this.issuerRequired = issuerRequired;
    }


    /**
     * Enable or disable certificate revocation checking (CRL/OCSP) for this trust manager only.
     *
     * @param revocationEnabled true to enable revocation checking
     */
    public void setRevocationEnabled(boolean revocationEnabled) {
        certificateVerifier.setRevocationEnabled(revocationEnabled);
    }


    /**
     * Enable or disable the strict revocation mode for this trust manager only: if true, certificates whose
     * revocation status can not be determined are rejected. See {@link CertificateVerifier#setRevocationStrict(boolean)}.
     *
     * @param revocationStrict true to reject certificates with an unknown revocation status
     */
    public void setRevocationStrict(boolean revocationStrict) {
        certificateVerifier.setRevocationStrict(revocationStrict);
    }

    
    /**
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];                    
    }
    
    
    /**
     * Gets the check result. The result is stored per thread: it is the result of the last check which ran in the
     * calling thread. With an {@link SSLEngine} the check may run in another thread (e.g. a delegated task).
     *
     * @return the check result of the last check of the calling thread
     */
    public int getCheckResult() {
        return certCheckResult.get();
    }        
    
    
    /**
     * Verifies a certificate chain.
     * 
     * @param chain a certificate chain
     * @param protocol the protocol
     * @throws CertificateException in case of error
     */
    public void verifyCertificateChain(X509Certificate[] chain, String protocol) throws CertificateException {
        verifyCertificateChain(chain, protocol, getHostname(), true);
    }


    /**
     * Verifies a certificate chain against the given host name.
     *
     * @param chain a certificate chain
     * @param protocol the protocol
     * @param server the expected server host name of this check, or {@code null} to skip the host name verification
     * @param isServerCheck true for a server certificate check, false for a client certificate check (no host name
     *     verification)
     * @throws CertificateException in case of error
     */
    private void verifyCertificateChain(X509Certificate[] chain, String protocol, String server, boolean isServerCheck) throws CertificateException {
        certCheckResult.set(CERT_NOT_CHECKED);
        int len = chain.length;
        if (len == 0) {
            return;
        }

        checkCertificateChain(chain);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Check client {} certificate(s)...", protocol);
        }
        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processCertificate(LOG::debug, null, chain);
        }

        // The first certificate in the chain, chain[0] is the subject certificate of the server.
        X509Certificate subjectcert = chain[0];
        
        // Retrieve the Common Name 'CN' for which the Server Certificate has been issued.
        String commonName = subjectcert.getSubjectX500Principal().getName();
        if (commonName == null) {
            certCheckResult.set(CERT_CHECKFAILED);
            logRejection("Fatal Error on Server Certificate Verification: ");
            throw new CertificateException("Fatal Error on Server Certificate Verification!");
        }
        
        if (!isServerCheck) {
            // client certificate: no host name verification
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client certificate check, no host name verification.");
            }
        } else if (server != null && !server.trim().isEmpty()) {
            boolean matches;
            try {
                matches = matchesHostname(subjectcert, server.trim());
            } catch (RuntimeException e) {
                logRejection("Invalid common name (" + commonName + "): ");
                certCheckResult.set(CERT_INVALIDCOMMONNAME);
                throw new CertificateException("Invalid common name: " + commonName + ": " + e.getMessage(), e);
            }

            // The subject alternative names (or as fallback the common name) have to match the server we want to contact
            if (!matches) {
                logRejection("Certificate [" + commonName + "] does not match the server name [" + server + "] on Server Certificate Verification: ");
                certCheckResult.set(CERT_INVALIDCOMMONNAME);
                throw new CertificateException("Certificate does not match the server name on Server Certificate Verification");
            }
        } else if (missingHostnameWarningLogged.compareAndSet(false, true)) {
            LOG.warn("No host name configured, host name verification is skipped! Use setHostname() to enable it.");
        }

        checkCertificate(subjectcert);

        if (chain.length > 1) {
            // get the CA which signed the Server Certificate
            for (int i = 1; i < chain.length; i++) {
                X509Certificate c = chain[i];

                if (!trustedCerts.contains(c)) {
                    certCheckResult.set(CERT_UNKNOWNCA);
                    logRejection("Unknown CA, Server Certificate Verification: ");
                    throw new CertificateException("Unknown CA, Server Certificate Verification!");
                }

                checkCACertificate(c);
                checkIssuerCertificate(c);
            }
        }

        certCheckResult.set(CERT_OK);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Checked successful client {} certificate(s).", protocol);
        }
    }
        
    
    /**
     * Checks the certificate
     * 
     * @param cert the certificate to test
     * @throws CertificateException In case of a certificate error
     */
    protected void checkCertificate(X509Certificate cert) throws CertificateException {
        String dn = cert.getIssuerX500Principal().getName();
        if (!trustedCerts.contains(cert)) {
            certCheckResult.set(CERT_UNKNOWNCA);
            logRejection("Unknown CA, Server Certificate Verification: ");
                
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unknown CA, Server Certificate for '{}':\n{}", dn, CertificateUtilFactory.getInstance().getConverter().formatPKCS7(cert));
            }

            throw new CertificateException("Unknown CA, Server Certificate Verification!");
        }
        
        try {
            // verify that the subject certificate is valid
            cert.checkValidity();
        } catch (CertificateExpiredException ex) {
            certCheckResult.set(CERT_CERTEXPIRED);
            logRejection("Certificate Expired on Server Certificate Verification: ");
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (CertificateNotYetValidException ex) {
            certCheckResult.set(CERT_CERTEXPIRED);
            logRejection("Certificate Expired on Server Certificate Verification: ");
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (Exception ex) {
            certCheckResult.set(CERT_CHECKFAILED);
            logRejection("Fatal Error on Server Certificate Verification: ");
            throw new CertificateException("Fatal Error on Server Certificate Verification!", ex);
        }
    }


    /**
     * Checks the validity of the trusted issuer of a CA certificate. A self-signed certificate is its own issuer and is not checked again.
     *
     * @param cacert the CA certificate
     * @throws CertificateException In case the issuer is expired or, if the issuer is required, not trusted
     */
    protected void checkIssuerCertificate(X509Certificate cacert) throws CertificateException {
        X509Certificate issuer = findTrustedIssuer(cacert);
        if (issuer == null) {
            if (issuerRequired) {
                certCheckResult.set(CERT_UNKNOWNCA);
                logRejection("Unknown CA, Server Certificate Verification: ");
                throw new CertificateException("Unknown CA, Server Certificate Verification!");
            }
            return;
        }

        if (!issuer.equals(cacert)) {
            checkCACertificate(issuer);
        }
    }


    /**
     * Log a rejected certificate check: one line at WARN, the stack trace only at DEBUG, so many rejected
     * handshakes do not flood the log.
     *
     * @param message the message
     */
    private void logRejection(String message) {
        String text = message.trim();
        if (text.endsWith(":")) {
            text = text.substring(0, text.length() - 1);
        }

        LOG.warn(text);
        if (LOG.isDebugEnabled()) {
            StackTrace.processStackTrace(LOG::debug, StackTrace.DEFAULT_EXCLUDES, message, 3);
        }
    }


    /**
     * Find the trusted certificate which issued the given certificate: its subject must be the issuer
     * of the certificate and its public key must verify the signature of the certificate.
     *
     * @param cert the certificate
     * @return the trusted issuer or null if it is not trusted
     */
    private X509Certificate findTrustedIssuer(X509Certificate cert) {
        // a trusted self-signed certificate is its own issuer: its signature was already verified with the chain
        if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) && trustedCerts.contains(cert)) {
            return cert;
        }

        for (X509Certificate candidate : trustedCerts) {
            if (candidate.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                try {
                    cert.verify(candidate.getPublicKey());
                    return candidate;
                } catch (GeneralSecurityException | RuntimeException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Trusted certificate [{}] did not sign the certificate: {}", candidate.getSubjectX500Principal(), e.getMessage());
                    }
                }
            }
        }
        return null;
    }


    /**
     * Checks the CA certificate
     * 
     * @param cacert the certificate to test
     * @throws CertificateException In case of a certificate error
     */
    protected void checkCACertificate(X509Certificate cacert) throws CertificateException {
        // verify that the CA certificate is valid
        try {
            cacert.checkValidity();
        } catch (CertificateExpiredException ex) {
            certCheckResult.set(CERT_CAEXPIRED);
            logRejection("CA Certificate Expired on Server Certificate Verification: ");
            throw new CertificateException("CA Certificate Expired on Server Certificate Verification!");
        } catch (CertificateNotYetValidException ex) {
            certCheckResult.set(CERT_CAEXPIRED);
            logRejection("CA Certificate Expired on Server Certificate Verification: ");
            throw new CertificateException("CA Certificate Expired on Server Certificate Verification");
        } catch (Exception ex) {
            certCheckResult.set(CERT_CHECKFAILED);
            logRejection("Fatal Error on Server Certificate Verification: ");
            throw new CertificateException("Fatal Error on Server Certificate Verification!", ex);
        }
    }


    /**
     * Checks the certificate chain
     * 
     * @param chain the chain
     * @throws CertificateException In case of a certificate error
     */
    protected void checkCertificateChain(X509Certificate[] chain) throws CertificateException {
        try {
            // verify that the subject certificate has been properly signed by the issuer;
            // only pass a consumer if debug is enabled, otherwise the chain description is built for nothing
            Consumer<String> consumer = null;
            if (LOG.isDebugEnabled()) {
                consumer = LOG::debug;
            }
            certificateVerifier.verifyCertificateChain(consumer, chain);
        } catch (SignatureException ex) {
            certCheckResult.set(CERT_INVALIDSIGNATURE);
            logRejection("Invalid Signature on Server Certificate Verification: ");
            throw new CertificateException("Invalid Signature Error on Server Certificate Verification!");
        } catch (CertificateExpiredException ex) {
            certCheckResult.set(CERT_CERTEXPIRED);
            logRejection("Certificate Expired on Server Certificate Verification: ");
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (CertificateNotYetValidException ex) {
            certCheckResult.set(CERT_CERTEXPIRED);
            logRejection("Certificate Expired on Server Certificate Verification: ");
            throw new CertificateException("Certificate Expired on Server Certificate Verification!");
        } catch (CertificateException ex) {
            if (!trustedCerts.contains(chain[chain.length - 1])) {
                // the verifier rejected the root certificate: report it as unknown CA
                certCheckResult.set(CERT_UNKNOWNCA);
                logRejection("Unknown CA, Server Certificate Verification: ");
                throw new CertificateException("Unknown CA, Server Certificate Verification!");
            }

            certCheckResult.set(CERT_CHECKFAILED);
            logRejection("Fatal Error on Server Certificate Verification: ");
            throw new CertificateException("Fatal Error on Server Certificate Verification!", ex);
        } catch (Exception ex) {
            certCheckResult.set(CERT_CHECKFAILED);
            logRejection("Fatal Error on Server Certificate Verification: ");
            throw new CertificateException("Fatal Error on Server Certificate Verification!", ex);
        }
    }


    /**
     * Check if the given certificate should be trusted and added to the trusted certificate list.
     *
     * <p><strong>WARNING:</strong> This default implementation uses a trust-on-first-use (TOFU)
     * policy and unconditionally returns {@code true}, accepting <em>any</em> server certificate
     * without CA validation. This is intentional for internal PKI / self-signed certificate
     * scenarios, but is <strong>not safe for production use against public CAs</strong>.
     * Subclasses must override this method to enforce a proper trust policy (e.g. pin to a
     * known certificate fingerprint or validate against a local trust store).</p>
     *
     * @param certificate the server certificate
     * @return true if the server certificate should be trusted
     */
    protected boolean trustServerCertificate(X509Certificate certificate) {
        return true;
    }    
    
    
    /**
     * Gets the host name used for hostname verification during server certificate checks.
     *
     * <p>Returns the host name set by the constructor or {@link #setHostname(String)}.
     * <strong>WARNING:</strong> if no host name is set ({@code null}), hostname verification is
     * <em>skipped entirely</em> and a warning is logged once. Subclasses may override this method
     * to provide the host name dynamically.</p>
     *
     * @return the expected server hostname, or {@code null} to skip hostname verification
     */
    protected String getHostname() {
        return hostname;
    }


    /**
     * Select the host name of a single check: a configured host name (see {@link #getHostname()}) wins,
     * otherwise the peer host of the connection is used.
     *
     * @param peerHost the peer host of the connection or null
     * @return the host name of the check or null to skip the host name verification
     */
    private String selectHostname(String peerHost) {
        String configuredHostname = getHostname();
        if (configuredHostname != null && !configuredHostname.trim().isEmpty()) {
            return configuredHostname;
        }
        return peerHost;
    }


    /**
     * Get the algorithm constraints of the connection: they are not checked by the JDK for an
     * {@link X509ExtendedTrustManager}, so this trust manager checks them itself.
     *
     * @param socket the socket or null
     * @return the algorithm constraints or null if there are none
     */
    private AlgorithmConstraints getAlgorithmConstraints(Socket socket) {
        if (socket instanceof SSLSocket && ((SSLSocket) socket).getSSLParameters() != null) {
            return ((SSLSocket) socket).getSSLParameters().getAlgorithmConstraints();
        }

        return null;
    }


    /**
     * Get the algorithm constraints of the connection: they are not checked by the JDK for an
     * {@link X509ExtendedTrustManager}, so this trust manager checks them itself.
     *
     * @param engine the engine or null
     * @return the algorithm constraints or null if there are none
     */
    private AlgorithmConstraints getAlgorithmConstraints(SSLEngine engine) {
        if (engine != null && engine.getSSLParameters() != null) {
            return engine.getSSLParameters().getAlgorithmConstraints();
        }

        return null;
    }


    /**
     * Check the signature algorithm and the public key of every certificate of the chain against the algorithm
     * constraints of the connection.
     *
     * @param chain the certificate chain
     * @param constraints the algorithm constraints or null
     * @throws CertificateException if an algorithm or a key of the chain is not permitted
     */
    private void checkAlgorithmConstraints(X509Certificate[] chain, AlgorithmConstraints constraints) throws CertificateException {
        if (constraints == null || chain == null) {
            return;
        }

        for (X509Certificate certificate : chain) {
            if (!constraints.permits(EnumSet.of(CryptoPrimitive.SIGNATURE), certificate.getSigAlgName(), null)
                    || !constraints.permits(EnumSet.of(CryptoPrimitive.SIGNATURE), certificate.getPublicKey())) {
                throw new CertificateException("Algorithm constraints check failed on certificate '" + certificate.getSubjectX500Principal().getName() + "'!");
            }
        }
    }


    /**
     * Get the peer host of a socket: the peer host of the handshake session if available, otherwise the host name of the remote address.
     *
     * @param socket the socket or null
     * @return the peer host or null
     */
    private String getPeerHost(Socket socket) {
        if (socket == null) {
            return null;
        }

        if (socket instanceof SSLSocket) {
            String peerHost = getPeerHost(((SSLSocket) socket).getHandshakeSession());
            if (peerHost != null) {
                return peerHost;
            }
        }

        if (socket.getInetAddress() != null) {
            return socket.getInetAddress().getHostName();
        }
        return null;
    }


    /**
     * Get the peer host of an engine: the peer host of the handshake session if available, otherwise the peer host of the engine.
     *
     * @param engine the engine or null
     * @return the peer host or null
     */
    private String getPeerHost(SSLEngine engine) {
        if (engine == null) {
            return null;
        }

        String peerHost = getPeerHost(engine.getHandshakeSession());
        if (peerHost != null) {
            return peerHost;
        }
        return engine.getPeerHost();
    }


    /**
     * Get the peer host of a handshake session.
     *
     * @param session the session or null
     * @return the peer host or null
     */
    private String getPeerHost(SSLSession session) {
        if (session == null) {
            return null;
        }
        return session.getPeerHost();
    }


    /**
     * Checks if the certificate matches the given host name (RFC 6125): if the certificate contains
     * DNS subject alternative names, only those are used, otherwise the most specific (last) common name (CN) is used
     * as fallback. An IP address (IPv4 or IPv6) only matches an IP address subject alternative name, compared as
     * address (e.g. {@code ::1} matches {@code 0:0:0:0:0:0:0:1}); it never matches a DNS name, a wildcard or the
     * common name. A wildcard is only supported as the complete left-most label (e.g. {@code *.example.com}).
     *
     * @param cert the certificate
     * @param host the host name
     * @return true if the certificate matches the host name
     * @throws CertificateException in case the subject alternative names can not be parsed
     */
    protected boolean matchesHostname(X509Certificate cert, String host) throws CertificateException {
        Collection<List<?>> subjectAlternativeNames = cert.getSubjectAlternativeNames();
        InetAddress hostAddress = parseIpAddress(host);
        if (hostAddress != null) {
            return matchesIpAddress(subjectAlternativeNames, hostAddress);
        }

        boolean hasDnsName = false;
        if (subjectAlternativeNames != null) {
            for (List<?> entry : subjectAlternativeNames) {
                if (entry != null && entry.size() >= 2 && entry.get(1) instanceof String && SAN_TYPE_DNS.equals(entry.get(0))) {
                    hasDnsName = true;
                    if (matchesDnsName((String) entry.get(1), host)) {
                        return true;
                    }
                }
            }
        }

        if (hasDnsName) {
            return false;
        }

        // fallback: the most specific (last) common name
        X500Name x500name = new X500Name(cert.getSubjectX500Principal().getName());
        RDN[] cns = x500name.getRDNs(BCStyle.CN);
        if (cns == null || cns.length == 0) {
            return false;
        }
        return matchesDnsName(IETFUtils.valueToString(cns[cns.length - 1].getFirst().getValue()), host);
    }


    /**
     * Checks if one of the IP address subject alternative names is the given address.
     *
     * @param subjectAlternativeNames the subject alternative names or null
     * @param hostAddress the address of the host
     * @return true if the address is one of the IP address subject alternative names
     */
    private boolean matchesIpAddress(Collection<List<?>> subjectAlternativeNames, InetAddress hostAddress) {
        if (subjectAlternativeNames == null) {
            return false;
        }

        for (List<?> entry : subjectAlternativeNames) {
            if (entry != null && entry.size() >= 2 && entry.get(1) instanceof String && SAN_TYPE_IP.equals(entry.get(0))) {
                InetAddress address = parseIpAddress((String) entry.get(1));
                if (address != null && address.equals(hostAddress)) {
                    return true;
                }
            }
        }

        return false;
    }


    /**
     * Parse an IP address literal (IPv4 or IPv6, optionally in brackets). No name lookup is done.
     *
     * @param value the value
     * @return the address or null if the value is no IP address literal
     */
    private InetAddress parseIpAddress(String value) {
        if (value == null) {
            return null;
        }

        String literal = value.trim();
        if (literal.startsWith("[") && literal.endsWith("]")) {
            literal = literal.substring(1, literal.length() - 1);
        }

        boolean isIpv4 = IPV4_PATTERN.matcher(literal).matches();
        boolean isIpv6 = literal.indexOf(':') >= 0 && IPV6_PATTERN.matcher(literal).matches();
        if (!isIpv4 && !isIpv6) {
            return null;
        }

        try {
            // the value is a literal, so no name lookup is done
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            return null;
        }
    }


    /**
     * Checks if a DNS name of a certificate matches the host name (case-insensitive). A wildcard is only
     * supported as the complete left-most label and matches exactly one label; it requires at least two
     * further labels (e.g. {@code *.com} is not accepted).
     *
     * @param inputPattern the DNS name from the certificate
     * @param inputHost the host name
     * @return true if it matches
     */
    protected boolean matchesDnsName(String inputPattern, String inputHost) {
        if (inputPattern == null || inputHost == null) {
            return false;
        }

        String pattern = stripTrailingDot(inputPattern.trim().toLowerCase(Locale.ROOT));
        String host = stripTrailingDot(inputHost.trim().toLowerCase(Locale.ROOT));
        if (pattern.isEmpty() || host.isEmpty()) {
            return false;
        }

        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // e.g. ".example.com"
            if (suffix.indexOf('.', 1) < 0 || suffix.indexOf('*') >= 0 || !host.endsWith(suffix)) {
                return false;
            }
            String label = host.substring(0, host.length() - suffix.length());
            return !label.isEmpty() && label.indexOf('.') < 0;
        }

        return pattern.equals(host);
    }


    /**
     * Removes a trailing dot of a fully qualified domain name
     *
     * @param name the name
     * @return the name without trailing dot
     */
    private String stripTrailingDot(String name) {
        if (name.endsWith(".")) {
            return name.substring(0, name.length() - 1);
        }
        return name;
    }
}
