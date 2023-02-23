package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
)

var pageSize = int(100)
var snowTime = "2006-01-02 15:04:05"
var resulExp = regexp.MustCompile(`errorCode=(?P<errorCode>\d+)&noOfResults=(?P<recordCount>\d+)`)

//var orderExp = regexp.MustCompile(`\d+_orderNumber=(?P<orderNumber>\d+)&\d+_orderStatus=(?P<orderStatus>[a-zA-Z ]+)&\d+_dateTime=(?P<orderDate>\d+)&\d+_1_status=(?P<certStatus>[a-zA-Z ]+)`)

var certExp = regexp.MustCompile(`(?:&\d+_\d+_(?:type|domain)=[^&]+)*&(?P<orderIndex>\d+)_(?P<certIndex>\d+)_status=(?P<certStatus>[^&]+)(?:&\d+_\d+_(?:lastStatusChange|notBefore|notAfter|certificateDuration|productTermStartDate|productTermEndDate|productTermDuration)=\d+)+(?:&\d+_\d+_serialNumber=(?P<certSerial>[^&]+))?`)
var orderExp = regexp.MustCompile(`&(?P<orderIndex>\d+)_orderNumber=(?P<orderNumber>\d+)&\d+_orderStatus=(?P<orderStatus>[^& ]+)&\d+_dateTime=(?P<orderDate>\d+)(?:&\d+_(?:organizationName|organizationalUnitName|postOfficeBox|streetAddress1|streetAddress2|streetAddress3|localityName|stateOrProvinceName|postalCode|countryName)=[^&]+)+`)

func main() {
	fmt.Println("Starting Job")

	//insertNewOrders()
	insertUpdateAllOrders()
	//updatePendingCertificates()
	//updateRevokedCertificates()
}

func getLastIssuedCertificate() UniqueCertificate {
	req, _ := http.NewRequest("GET", "https://{{domain}}.service-now.com/api/now/table/cmdb_ci_certificate?sysparm_query=discovery_source%3DSectigo%5EORDERBYDESCvalid_from&sysparm_limit=1", nil)

	req.Header.Add("Authorization", "basic auth")
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result QueryResult
	json.Unmarshal(body, &result)

	return result.Data[0]
}

func insertNewOrders() {
	cert := getLastIssuedCertificate()
	dt, _ := time.Parse(snowTime, cert.NotBefore)

	formValues := url.Values{
		"notBefore": {fmt.Sprintf("%d", dt.Unix()+1)},
	}

	processOrders(formValues)
}

func insertUpdateAllOrders() {
	formValues := url.Values{
		"loginName":        {"username"},
		"loginPassword":    {"password"},
		"firstResultNo":    {"0"},
		"lastResultNo":     {"0"},
		"showStatusesOnly": {"Y"},
	}

	resp, err := http.PostForm("https://secure.trust-provider.com/products/!WebHostReport", formValues)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	match := resulExp.FindStringSubmatch(string(body))

	if match[resulExp.SubexpIndex("errorCode")] != "0" {
		log.Fatal("Expected no error, received errorCode", resulExp.SubexpIndex("errorCode"))
	}

	cnt, _ := strconv.ParseInt(match[resulExp.SubexpIndex("recordCount")], 10, 0)

	for i := 0; i < int(math.Ceil(float64(cnt/int64(pageSize)))); i++ {
		formValues["firstResultNo"][0] = strconv.Itoa(i * pageSize)
		formValues["lastResultNo"][0] = strconv.Itoa((i * pageSize) + (pageSize - 1))

		formValues = url.Values{
			"firstResultNo": {strconv.Itoa(i * pageSize)},
			"lastResultNo":  {strconv.Itoa((i * pageSize) + pageSize)},
		}

		processOrders(formValues)
	}
}

func insertUpdateCertificate(orderDate time.Time, orderNumber string, certificateStatus string, certificateSerialNumber string) {
	cert := UniqueCertificate{
		OrderDate:    orderDate.Format(snowTime),
		OrderNumber:  orderNumber,
		SerialNumber: strings.ToLower(certificateSerialNumber),
	}

	switch certificateStatus {
	case "Expired":
		cert.State = "retired"
	case "Revoked":
		cert.State = "revoked"
	case "Valid":
		cert.State = "issued"
	default:
		return
	}

	var payload Payload

	payload.Items = append(payload.Items, ConfigurationItem{
		ClassName: "cmdb_ci_certificate",
		Values:    &cert,
	})

	if certificateStatus == "Valid" {
		form := url.Values{
			"loginName":        {"username"},
			"loginPassword":    {"password"},
			"orderNumber":      {orderNumber},
			"queryType":        {"1"},
			"responseType":     {"2"},
			"responseEncoding": {"1"},
		}

		resp, err := http.PostForm("https://secure.trust-provider.com/products/download/CollectSSL", form)

		// REST failed
		if err != nil {
			log.Fatal(err)
		}

		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		p7, err := pkcs7.Parse(body)

		// Parsing certificates failed
		if err != nil {
			log.Fatal(err)
		}

		cert.Name = p7.Certificates[0].Subject.CommonName
		cert.Fingerprint = fmt.Sprintf("%x", sha256.Sum256(p7.Certificates[0].Raw))
		cert.FingerprintAlgorithm = "SHA256"
		cert.SignatureAlgorithm = p7.Certificates[0].SignatureAlgorithm.String()
		cert.NotBefore = p7.Certificates[0].NotBefore.Format(snowTime)
		cert.NotAfter = p7.Certificates[0].NotAfter.Format(snowTime)
		cert.IsCa = p7.Certificates[0].IsCA
		cert.Version = p7.Certificates[0].Version
		cert.IssuerCommonName = p7.Certificates[0].Issuer.CommonName
		cert.IssuerDistinguishedName = p7.Certificates[0].Issuer.String()
		cert.SubjectCommonName = p7.Certificates[0].Subject.CommonName
		cert.SubjectDistinguishedName = p7.Certificates[0].Subject.String()

		for _, name := range p7.Certificates[0].DNSNames {
			dn := ConfigurationItem{
				ClassName: "cmdb_ci_dns_name",
				Values:    map[string]string{"name": name},
			}

			rs := Relationship{Parent: len(payload.Items), Child: 0, Type: "Uses::Used by"}

			payload.Items = append(payload.Items, dn)
			payload.Relations = append(payload.Relations, rs)
		}
	}

	body, _ := json.Marshal(payload)
	buffer := bytes.NewBuffer(body)

	req, _ := http.NewRequest("POST", "https://{{domain}}.service-now.com/api/now/identifyreconcile?sysparm_data_source=Sectigo", buffer)

	req.Header.Add("Authorization", "basic auth")
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)

	// REST failed
	if err != nil {
		log.Print(err)
	}

	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		body, _ = io.ReadAll(resp.Body)

		log.Print(string(body))
	}
}

func processOrders(formValues url.Values) {
	formValues.Add("loginName", "username")
	formValues.Add("loginPassword", "password")

	resp, err := http.PostForm("https://secure.trust-provider.com/products/!WebHostReport", formValues)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	match := resulExp.FindStringSubmatch(string(body))

	if match[resulExp.SubexpIndex("errorCode")] != "0" {
		log.Fatal("Expected no error, received errorCode", resulExp.SubexpIndex("errorCode"))
	}

	ordMatches := orderExp.FindAllStringSubmatch(string(body), -1)
	certMatches := certExp.FindAllStringSubmatch(string(body), -1)

	// This may be problematic in the future if there is more than 1 certificate in the order
	for _, ordMatch := range ordMatches {
		for _, certMatch := range certMatches {
			if certMatch[1] == ordMatch[1] {
				odts, _ := strconv.ParseInt(ordMatch[4], 10, 64)
				insertUpdateCertificate(time.Unix(odts, 0), ordMatch[2], certMatch[3], certMatch[4])
				break
			}
		}
	}
}

func updateRevokedCertificates() {

}

type ConfigurationItem struct {
	ClassName string `json:"className"`
	Values    any    `json:"values"`
}

type Payload struct {
	Items     []ConfigurationItem `json:"items"`
	Relations []Relationship      `json:"relations"`
}

type Relationship struct {
	Parent int    `json:"parent"`
	Child  int    `json:"child"`
	Type   string `json:"type"`
}

type QueryResult struct {
	Data []UniqueCertificate `json:"result"`
}

type UniqueCertificate struct {
	OrderDate                string `json:"order_date"`
	OrderNumber              string `json:"po_number"`
	Name                     string `json:"name"`
	Fingerprint              string `json:"fingerprint"`
	FingerprintAlgorithm     string `json:"fingerprint_algorithm"`
	SignatureAlgorithm       string `json:"signature_algorithm"`
	SerialNumber             string `json:"serial_number"`
	NotBefore                string `json:"valid_from"`
	NotAfter                 string `json:"valid_to"`
	State                    string `json:"state"`
	IsCa                     bool   `json:"is_ca"`
	Version                  int    `json:"version"`
	IssuerCommonName         string `json:"issuer_common_name"`
	IssuerDistinguishedName  string `json:"issuer_distinguished_name"`
	SubjectCommonName        string `json:"subject_common_name"`
	SubjectDistinguishedName string `json:"subject_distinguished_name"`
}
