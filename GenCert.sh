#!/usr/bin/env bash
set -euo pipefail

# ==============================================
# build-nifi-certs.sh
# Produces a CA and signed keystores/truststores for:
#  - stage-nifi-01  (192.168.149.74)
#  - stage-nifi-02  (192.168.149.75)
#  - stage-nifi-03  (192.168.149.76)
#  - nifi-reg       (192.168.149.77)
#
# Output structure: certs/
#   certs/ca/
#   certs/<host>/
# ==============================================

# -------------------------
# Safety and environment
# -------------------------
WORKDIR="$(pwd)/certs"
mkdir -p "$WORKDIR"
OPENSSL_BIN="$(command -v openssl || true)"
KEYTOOL_BIN="$(command -v keytool || true)"

if [[ -z "$OPENSSL_BIN" || -z "$KEYTOOL_BIN" ]]; then
  echo "error: openssl and keytool are required. install them and re-run."
  exit 1
fi

# -------------------------
# Hosts / IPs (fixed from user)
# -------------------------
HOSTS=("stage-nifi-01" "stage-nifi-02" "stage-nifi-03" "nifi-reg")
IPS=("192.168.149.74" "192.168.149.75" "192.168.149.76" "192.168.149.77")

# -------------------------
# CONFIG - Change these before running
# -------------------------
CA_SUBJ="/C=IR/ST=Tehran/L=Tehran/O=Vasl/OU=Platform/CN=VaslNiFiCA"
CA_DAYS=3650
SERVER_DAYS=1095
ADMIN_DAYS=3650

# Passwords - CHANGE THESE to secure values BEFORE running
# (You can set them as env variables to avoid seeing in shell history,
# e.g. export KEYSTORE_PASS='...'; ./build-nifi-certs.sh)
KEYSTORE_PASS="${KEYSTORE_PASS:-r2rifhe8Ct2DtIwdqdwqfeYhvu}"
TRUSTSTORE_PASS="${TRUSTSTORE_PASS:-wefwBLR4gOwfwfewfIJpA}"
ADMIN_P12_PASS="${ADMIN_P12_PASS:-FORexamplePass}"

# Output locations inside WORKDIR
CA_DIR="$WORKDIR/ca"
mkdir -p "$CA_DIR"

echo "Working dir: $WORKDIR"
echo "CA dir: $CA_DIR"

# -------------------------
# 1) Create CA
# -------------------------
CA_KEY="$CA_DIR/ca-key.pem"
CA_CERT="$CA_DIR/ca-cert.pem"
CA_SERIAL="$CA_DIR/ca.srl"

if [[ -f "$CA_KEY" ]] || [[ -f "$CA_CERT" ]]; then
  echo "CA already exists in $CA_DIR - skipping creation (delete to recreate)."
else
  echo "[1/6] Generating CA private key..."
  "$OPENSSL_BIN" genrsa -out "$CA_KEY" 4096
  echo "[2/6] Generating CA self-signed cert..."
  "$OPENSSL_BIN" req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$CA_DAYS" -subj "$CA_SUBJ" -out "$CA_CERT"
  chmod 640 "$CA_KEY" "$CA_CERT"
  echo "CA generated: $CA_CERT"
fi

# -------------------------
# 2) For each host: key, csr, sign, keystore, truststore
# -------------------------
for idx in "${!HOSTS[@]}"; do
  HOST="${HOSTS[$idx]}"
  IP="${IPS[$idx]}"
  HDIR="$WORKDIR/$HOST"
  mkdir -p "$HDIR"
  echo
  echo "------ Processing $HOST ($IP) ------"
  cd "$HDIR"

  # filenames
  KEY_FILE="${HOST}.key"
  CSR_FILE="${HOST}.csr"
  CRT_FILE="${HOST}.crt"
  P12_FILE="${HOST}.keystore.p12"
  TRUST_JKS="${HOST}.truststore.jks"
  CSR_CONF="${HOST}_csr.conf"
  V3_EXT="${HOST}_v3ext.conf"

  # 2.1 create private key
  echo "[+] Generating private key for $HOST..."
  "$OPENSSL_BIN" genrsa -out "$KEY_FILE" 2048
  chmod 600 "$KEY_FILE"

  # 2.2 CSR config with SAN (DNS + IP)
  cat > "$CSR_CONF" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C=DE
ST=State
L=City
O=MyOrg
OU=Infra
CN=${HOST}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${HOST}
IP.1  = ${IP}
EOF

  # 2.3 generate CSR
  echo "[+] Generating CSR..."
  "$OPENSSL_BIN" req -new -key "$KEY_FILE" -out "$CSR_FILE" -config "$CSR_CONF"

  # 2.4 v3 ext for SAN and usage
  cat > "$V3_EXT" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${HOST}
IP.1  = ${IP}
EOF

  # 2.5 Sign CSR with CA
  echo "[+] Signing CSR with CA..."
  "$OPENSSL_BIN" x509 -req -in "$CSR_FILE" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -CAserial "$CA_SERIAL" \
    -out "$CRT_FILE" -days "$SERVER_DAYS" -sha256 -extfile "$V3_EXT"

  chmod 640 "$CRT_FILE"

  # 2.6 create PKCS12 keystore (private key + cert + CA)
  echo "[+] Creating PKCS12 keystore..."
  "$OPENSSL_BIN" pkcs12 -export \
    -in "$CRT_FILE" \
    -inkey "$KEY_FILE" \
    -certfile "$CA_CERT" \
    -name "$HOST" \
    -passout pass:"$KEYSTORE_PASS" \
    -out "$P12_FILE"

  chmod 640 "$P12_FILE"

  # 2.7 Create truststore (JKS) and import CA cert
  echo "[+] Creating truststore (JKS) with CA..."
  # if truststore exists remove first to avoid prompts - safe as per host dir
  if [[ -f "$TRUST_JKS" ]]; then rm -f "$TRUST_JKS"; fi

  "$KEYTOOL_BIN" -importcert -trustcacerts -alias "nifi-ca" -file "$CA_CERT" \
    -keystore "$TRUST_JKS" -storepass "$TRUSTSTORE_PASS" -noprompt

  chmod 640 "$TRUST_JKS"

  echo "[+] $HOST done. Files in $HDIR:"
  ls -1 "$HDIR" | sed -n '1,200p'
done

# -------------------------
# 3) Create admin client certificate (admin.p12) for browser login
# -------------------------
echo
echo "------ Creating admin client certificate (admin.p12) ------"
ADMIN_DIR="$WORKDIR/admin"
mkdir -p "$ADMIN_DIR"
cd "$ADMIN_DIR"
ADMIN_KEY="admin.key"
ADMIN_CSR="admin.csr"
ADMIN_CRT="admin.crt"
ADMIN_P12="admin.p12"
ADMIN_SUBJ="/C=DE/ST=State/L=City/O=MyOrg/OU=Infra/CN=admin"

# create admin key + csr
"$OPENSSL_BIN" genrsa -out "$ADMIN_KEY" 2048
"$OPENSSL_BIN" req -new -key "$ADMIN_KEY" -out "$ADMIN_CSR" -subj "$ADMIN_SUBJ"

cat > admin_v3ext.conf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:admin
EOF

"$OPENSSL_BIN" x509 -req -in "$ADMIN_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$ADMIN_CRT" -days "$ADMIN_DAYS" -sha256 -extfile admin_v3ext.conf

# package for browser
"$OPENSSL_BIN" pkcs12 -export -out "$ADMIN_P12" -inkey "$ADMIN_KEY" -in "$ADMIN_CRT" -certfile "$CA_CERT" -name "nifi-admin" -passout pass:"$ADMIN_P12_PASS"

chmod 640 "$ADMIN_P12"
echo "[+] admin.p12 created at: $ADMIN_DIR/$ADMIN_P12"
echo "    -> Import this file into your browser (use password set in ADMIN_P12_PASS)"
echo "    -> Use DN: CN=admin, OU=Infra, O=MyOrg, L=City, ST=State, C=DE as Initial Admin Identity in authorizers.xml"

# -------------------------
# 4) Summary & next-steps printed to console
# -------------------------
echo
echo "======================================"
echo "All certs created under: $WORKDIR"
echo
for h in "${HOSTS[@]}"; do
  echo " - $WORKDIR/$h :"
  ls -1 "$WORKDIR/$h" | sed 's/^/    /'
done
echo " - CA:"
ls -1 "$CA_DIR" | sed 's/^/    /'
echo " - admin client cert:"
ls -1 "$ADMIN_DIR" | sed 's/^/    /'

cat <<EOF

=== NEXT STEPS (manual tasks to finish deploy) ===

1) Copy each host's keystore and truststore to the corresponding NiFi server.
   Example (run from machine where certs/ created):
     scp $WORKDIR/stage-nifi-01/stage-nifi-01.keystore.p12 root@192.168.149.74:/opt/nifi/ssl/
     scp $WORKDIR/stage-nifi-01/stage-nifi-01.truststore.jks root@192.168.149.74:/opt/nifi/ssl/

   Repeat for stage-nifi-02, stage-nifi-03, nifi-reg.

2) On each NiFi server:
     sudo mkdir -p /opt/nifi/ssl
     sudo chown -R nifi:nifi /opt/nifi/ssl
     sudo chmod 640 /opt/nifi/ssl/*

3) Edit NIFI_HOME/conf/nifi.properties on each node:
   Example properties for stage-nifi-01:
     nifi.web.https.host=stage-nifi-01
     nifi.web.https.port=8443
     nifi.security.keystore=/opt/nifi/ssl/stage-nifi-01.keystore.p12
     nifi.security.keystoreType=PKCS12
     nifi.security.keystorePasswd=${KEYSTORE_PASS}
     nifi.security.truststore=/opt/nifi/ssl/stage-nifi-01.truststore.jks
     nifi.security.truststoreType=JKS
     nifi.security.truststorePasswd=${TRUSTSTORE_PASS}

   (Change hostnames and file names per node.)

4) Set Initial Admin Identity in conf/authorizers.xml:
     <property name="Initial Admin Identity">CN=admin, OU=Infra, O=MyOrg, L=City, ST=State, C=DE</property>

   Then import admin.p12 in your browser (you may need OS-level import).
   Login to https://stage-nifi-01:8443/nifi and choose the client cert when prompted.

5) NiFi Registry:
   Copy nifi-reg.keystore.p12 and nifi-reg.truststore.jks to the registry server (/opt/nifi-registry/ssl or similar)
   Edit nifi-registry.properties / bootstrap config to point to keystore/truststore with passwords.

6) If Java clients connect to NiFi, import CA into their JVM truststore or distribute the truststore.jks produced.

7) Check logs on startup:
   NIFI_HOME/logs/nifi-app.log
   NIFI_HOME/logs/nifi-bootstrap.log

======================================
EOF

echo "Done. Remember to change all placeholder passwords and to secure CA key ($CA_KEY)."

