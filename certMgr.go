package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	action     = flag.String("action", "tree", "Action target in tree map. Valid values are tree, get, add, del")
	target     = flag.String("target", "", "Slash-separated node path in tree, e.g. 0/2/1")
	name       = flag.String("name", "", "Common Name in certificate")
	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	days       = flag.Int("days", 365, "Days that certificate is valid from now")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits    = flag.Int("rsa", 2048, "Size of RSA key to generate. Ignored if --ecc is set")
	ecdsaCurve = flag.String("ecc", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384")
)

var logger = log.New(os.Stdout, "  ", log.LstdFlags|log.Lshortfile)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		fmt.Printf("Wrong private key type %v\n", priv)
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			logger.Fatalf("Unable to marshal ECDSA private key: %v\n", err)
			os.Exit(-1)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func loadPemBlockKey(data string) (priv interface{}, err error) {
	p, _ := pem.Decode([]byte(data))
	switch p.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(p.Bytes)
		if err != nil {
			logger.Fatalf("x509.ParsePKCS1PrivateKey failed, %v\n", err)
			os.Exit(-1)
		}
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(p.Bytes)
		if err != nil {
			logger.Fatalf("x509.ParseECPrivateKey failed, %v\n", err)
			os.Exit(-1)
		}
	default:
		logger.Fatalf("Invalid private key type, %v\n", p.Type)
		os.Exit(-1)
	}
	return
}

type CertTreeNode struct {
	Child      map[string]*CertTreeNode
	IsCA       bool
	CommonName string
	CertString string
	PrivateKey string
	KeyType    string
	ValidTime  time.Time
	ExpireTime time.Time
	ChildIndex int
	Name       string // name in parent child map
}

func NewCertTreeNode() *CertTreeNode {
	return &CertTreeNode{
		Child: make(map[string]*CertTreeNode),
	}
}

func (this *CertTreeNode) PrintTree(ident int) {
	prefix := ""
	for i := 0; i < ident; i++ {
		prefix = prefix + "|  "
	}
	fmt.Printf("%s|- [%s] %s (%s, CA=%v) %s\n", prefix, this.Name, this.CommonName, this.KeyType, this.IsCA, this.ExpireTime.Format("Jan 2 15:04:05 2006"))

	for _, c := range this.Child {
		c.PrintTree(ident + 1)
	}
}

func (this *CertTreeNode) GenCert(priv interface{}, hosts []string, d time.Duration, ca *CertTreeNode) error {
	this.ValidTime = time.Now()
	this.ExpireTime = this.ValidTime.Add(d)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Printf("rand.Int failed, %v\n", err)
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"AnyConnect Co., Ltd."},
			Locality:     []string{"Los Angeles"},
			Province:     []string{"California"},
			CommonName:   this.CommonName,
		},
		NotBefore: this.ValidTime,
		NotAfter:  this.ExpireTime,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if this.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Save private key
	buffer := bytes.NewBufferString("")
	pem.Encode(buffer, pemBlockForKey(priv))
	this.PrivateKey = buffer.String()

	var parentCert *x509.Certificate
	var parentCertKey interface{}
	if ca == nil {
		// Self signed root
		parentCert = &template
		parentCertKey = priv
	} else {
		// Load parent cert to sign leaf
		p, _ := pem.Decode([]byte(ca.CertString))
		parentCert, err = x509.ParseCertificate(p.Bytes)
		if err != nil {
			logger.Fatalf("x509.ParseCertificate failed, %v\n", err)
			os.Exit(-1)
		}

		parentCertKey, err = loadPemBlockKey(ca.PrivateKey)
		if err != nil {
			logger.Fatalf("loadPemBlockKey failed, %v\n", err)
			os.Exit(-1)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, publicKey(priv), parentCertKey)
	if err != nil {
		logger.Printf("x509.CreateCertificate failed, %v\n", err)
		return err
	}

	buffer.Reset()
	pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	this.CertString = buffer.String()
	return nil
}

func (this *CertTreeNode) GetCertificateChain(relativePath string) string {
	var node *CertTreeNode
	node = this
	certString := this.CertString
	relativePath = strings.TrimPrefix(relativePath, "/")
	if relativePath == "" {
		return certString
	}

	idxs := strings.Split(relativePath, "/")
	for _, s := range idxs {
		node = node.Child[s]
		certString = node.CertString + certString
	}
	return certString
}

func ReadDiskFile(filepath string) ([]byte, error) {
	if _, err := os.Stat(filepath + ".tmp"); !os.IsNotExist(err) {
		logger.Fatalf("Previous temp file(%s) status exists, please handle it first.", filepath)
		os.Exit(-1)
	}
	return ioutil.ReadFile(filepath)
}

func WriteDiskFile(filepath string, data []byte) error {
	err := ioutil.WriteFile(filepath+".tmp", data, 0600)
	if err != nil {
		return err
	}
	return os.Rename(filepath+".tmp", filepath)
}

func CheckNotEmptyString(name string, s *string) {
	if s == nil || *s == "" {
		logger.Fatalf("Must set value to param %s", name)
		os.Exit(-1)
	}
}

func FindNodeInTree(root *CertTreeNode, path string) (node, parent *CertTreeNode) {
	node = root
	parent = root
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return
	}
	idxs := strings.Split(path, "/")
	for _, s := range idxs {
		if node != root {
			parent = node
		}
		node = node.Child[s]
	}
	return
}

func main() {
	flag.Parse()

	certStatusFile := "./certStatus.json"

	var certStatus *CertTreeNode
	statusContent, err := ReadDiskFile(certStatusFile)
	if os.IsNotExist(err) {
		// First load, create root certificate
		certStatus = NewCertTreeNode()
		certStatus.KeyType = "ECC-P256"
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			logger.Fatalf("ecdsa.GenerateKey failed, %v\n", err)
			os.Exit(-1)
		}
		certStatus.IsCA = true
		certStatus.CommonName = "AnyConnect Self Signed Root"
		certStatus.Name = "Root"
		err = certStatus.GenCert(priv, []string{}, 50*365*24*time.Hour, nil)
		if err != nil {
			logger.Fatalf("GenCert for root failed, %v\n", err)
			os.Exit(-1)
		}
	} else {
		certStatus = NewCertTreeNode()
		err = json.Unmarshal(statusContent, certStatus)
		if err != nil {
			logger.Fatalf("Parse status file failed, %v\n", err)
			os.Exit(-1)
		}
	}

	switch *action {
	case "tree":
		certStatus.PrintTree(0)

	case "get":
		node, _ := FindNodeInTree(certStatus, *target)
		certString := certStatus.GetCertificateChain(*target)
		err = WriteDiskFile("./"+node.CommonName+".crt", []byte(certString))
		if err != nil {
			logger.Println("Unable to write cert into file")
			fmt.Printf("Certificate:\n%s\n", certString)
		}
		err = WriteDiskFile("./"+node.CommonName+".key", []byte(node.PrivateKey))
		if err != nil {
			logger.Println("Unable to write private key into file")
			fmt.Printf("Private Key:\n%s\n", node.CertString)
		}

	case "add":
		CheckNotEmptyString("name", name)
		hosts := []string{}
		if *host != "" {
			hosts = strings.Split(*host, ",")
		}

		parent, _ := FindNodeInTree(certStatus, *target)
		if parent.IsCA == false {
			logger.Fatalln("Parent isn't is CA")
			os.Exit(-1)
		}

		childCert := NewCertTreeNode()
		childCert.Name = strconv.Itoa(parent.ChildIndex)
		childCert.IsCA = *isCA
		childCert.CommonName = *name

		var priv interface{}
		var err error
		switch *ecdsaCurve {
		case "":
			priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
			childCert.KeyType = "RSA" + strconv.Itoa(*rsaBits)
		case "P224":
			priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
			childCert.KeyType = "ECC-P224"
		case "P256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			childCert.KeyType = "ECC-P256"
		case "P384":
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			childCert.KeyType = "ECC-P384"
		default:
			logger.Fatalf("Unrecognized elliptic curve: %q\n", *ecdsaCurve)
			os.Exit(1)
		}

		err = childCert.GenCert(priv, hosts, time.Duration(*days)*time.Hour*24, parent)
		if err != nil {
			logger.Fatalf("GenCert for %s failed, %v\n", *name, err)
			os.Exit(1)
		}

		parent.ChildIndex += 1
		parent.Child[childCert.Name] = childCert
		certString := certStatus.GetCertificateChain(*target + "/" + childCert.Name)
		err = WriteDiskFile("./"+childCert.CommonName+".crt", []byte(certString))
		if err != nil {
			logger.Println("Unable to write cert into file")
			fmt.Printf("Certificate:\n%s\n", certString)
		}
		err = WriteDiskFile("./"+childCert.CommonName+".key", []byte(childCert.PrivateKey))
		if err != nil {
			logger.Println("Unable to write private key into file")
			fmt.Printf("Private Key:\n%s\n", childCert.CertString)
		}

	case "del":
		node, parent := FindNodeInTree(certStatus, *target)
		if len(node.Child) != 0 {
			logger.Fatalln("Can't remove cert that has child")
			os.Exit(-1)
		}
		if node == certStatus {
			logger.Fatalln("Please remove status file if you want to delete root node")
			os.Exit(-1)
		}
		delete(parent.Child, node.Name)

	default:
		logger.Fatalf("Invalid action %s", *action)
		os.Exit(-1)
	}

	data, err := json.Marshal(certStatus)
	if err != nil {
		logger.Fatalf("json.Marshal status file failed, %v\n", err)
		os.Exit(-1)
	}
	err = WriteDiskFile(certStatusFile, data)
	if err != nil {
		logger.Fatalf("Write status file failed, %v\n", err)
	}
}
