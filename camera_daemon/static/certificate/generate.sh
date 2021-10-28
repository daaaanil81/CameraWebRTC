export EXTFILE='extfile.conf'
echo 'subjectAltName = IP:192.168.1.13\nbasicConstraints = critical,CA:true' > "${EXTFILE}"

export SERVER_NAME='danil_petrov'
openssl ecparam -name prime256v1 -genkey -noout -out "${SERVER_NAME}.pem"
openssl req -key "${SERVER_NAME}.pem" -new -sha256 -subj '/C=NL' -out "${SERVER_NAME}.csr"
openssl x509 -req -in "${SERVER_NAME}.csr" -extfile "${EXTFILE}" -days 365 -signkey "${SERVER_NAME}.pem" -sha256 -out "${SERVER_NAME}.pub.pem"

rm "${EXTFILE}" "${SERVER_NAME}.csr"

###cat danil_petrov.key > danil_petrov.pem
###cat danil_petrov.crt >> danil_petrov.pem
