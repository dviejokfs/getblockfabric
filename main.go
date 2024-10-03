package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"

	"testgetblockorderer/internal/fabric/bccsp/utils"
	"testgetblockorderer/internal/fabric/common/crypto"
	"testgetblockorderer/internal/fabric/protoutil"

	"github.com/hyperledger/fabric-config/protolator"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"

	// "github.com/hyperledger/fabric/bccsp/utils"
	// "github.com/hyperledger/fabric/common/crypto"
	"flag"
	"strconv"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// OrdererConfig holds the configuration for connecting to an orderer
type OrdererConfig struct {
	Address     string
	TLSCertPath string
	MspID       string
	PrivateKey  string
	Certificate string
}

func main() {
	// Define command-line flags
	address := flag.String("address", "", "Orderer address")
	tlsCertPath := flag.String("tlscert", "", "Path to TLS certificate")
	mspID := flag.String("mspid", "", "MSP ID")
	privateKey := flag.String("privatekey", "", "Path to private key")
	certificate := flag.String("cert", "", "Path to certificate")
	channelID := flag.String("channel", "", "Channel ID")
	blockNumberStr := flag.String("block", "", "Block number to fetch")

	// Parse the flags
	flag.Parse()

	// Validate required flags
	if *address == "" || *tlsCertPath == "" || *mspID == "" || *privateKey == "" || *certificate == "" || *channelID == "" || *blockNumberStr == "" {
		fmt.Println("All flags are required")
		flag.PrintDefaults()
		return
	}

	// Parse block number
	blockNumber, err := strconv.ParseUint(*blockNumberStr, 10, 64)
	if err != nil {
		fmt.Printf("Invalid block number: %v\n", err)
		return
	}

	// Configure the orderer connection details
	ordererConfig := OrdererConfig{
		Address:     *address,
		TLSCertPath: *tlsCertPath,
		MspID:       *mspID,
		PrivateKey:  *privateKey,
		Certificate: *certificate,
	}

	// Connect to the orderer
	conn, err := connectToOrderer(ordererConfig)
	if err != nil {
		fmt.Printf("Failed to connect to orderer: %v\n", err)
		return
	}
	defer conn.Close()

	// Fetch the block
	block, err := fetchBlockFromOrderer(conn, *channelID, blockNumber, ordererConfig)
	if err != nil {
		fmt.Printf("Failed to fetch block: %v\n", err)
		return
	}
	blockBytes, err := proto.Marshal(block)
	if err != nil {
		fmt.Printf("Failed to marshal block: %v\n", err)
		return
	}
	// write file to block_<blockNumber>.pb
	err = os.WriteFile(fmt.Sprintf("block_%d.pb", blockNumber), blockBytes, 0644)
	if err != nil {
		fmt.Printf("Failed to write block to file: %v\n", err)
		return
	}
	var buf bytes.Buffer
	err = protolator.DeepMarshalJSON(&buf, block)
	if err != nil {
		fmt.Printf("Failed to marshal block to JSON: %v\n", err)
		return
	}
	os.WriteFile(fmt.Sprintf("block_%d.json", blockNumber), buf.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Failed to write block to file: %v\n", err)
		return
	}
	log.Printf("Successfully fetched block number %d\n", blockNumber)
	log.Printf("Successfully write file to block_%d.json\n", blockNumber)
	fmt.Printf("Successfully fetched block number %d\n", blockNumber)
	// log about write file to block_<blockNumber>.pb
	fmt.Printf("Successfully write file to block_%d.pb\n", blockNumber)
}

func connectToOrderer(config OrdererConfig) (*grpc.ClientConn, error) {
	// Load the TLS certificate
	cert, err := ioutil.ReadFile(config.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(cert) {
		return nil, fmt.Errorf("failed to add certificate to pool")
	}

	// Create TLS credentials
	creds := credentials.NewClientTLSFromCert(certPool, "")

	// Establish gRPC connection
	conn, err := grpc.Dial(config.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to orderer: %v", err)
	}

	return conn, nil
}

func fetchBlockFromOrderer(conn *grpc.ClientConn, channelID string, blockNumber uint64, config OrdererConfig) (*common.Block, error) {
	client := ab.NewAtomicBroadcastClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Deliver(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create deliver stream: %v", err)
	}

	// Create seek info for the specific block
	seekInfo := &ab.SeekInfo{
		Start: &ab.SeekPosition{
			Type: &ab.SeekPosition_Specified{
				Specified: &ab.SeekSpecified{
					Number: blockNumber,
				},
			},
		},
		Stop: &ab.SeekPosition{
			Type: &ab.SeekPosition_Specified{
				Specified: &ab.SeekSpecified{
					Number: blockNumber,
				},
			},
		},
		Behavior: ab.SeekInfo_BLOCK_UNTIL_READY,
	}

	// Create signed envelope
	envelope, err := createSignedEnvelope(channelID, config, seekInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed envelope: %v", err)
	}

	if err := stream.Send(envelope); err != nil {
		return nil, fmt.Errorf("failed to send seek request: %v", err)
	}

	response, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive block: %v", err)
	}

	switch response.Type.(type) {
	case *ab.DeliverResponse_Block:
		return response.GetBlock(), nil
	case *ab.DeliverResponse_Status:
		return nil, fmt.Errorf("received status: %v", response.GetStatus())
	default:
		return nil, fmt.Errorf("unexpected response type")
	}
}

func createSignedEnvelope(channelID string, config OrdererConfig, seekInfo *ab.SeekInfo) (*common.Envelope, error) {

	cert, certBytes, err := GetCertificate(config.Certificate)
	if err != nil {
		return nil, errors.Wrapf(err, "error get certificate")
	}

	privateKey, err := GetPrivateKey(config.PrivateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "error get private key")
	}

	id := &msp.SerializedIdentity{
		Mspid:   config.MspID,
		IdBytes: certBytes,
	}

	name, err := proto.Marshal(id)
	if err != nil {
		return nil, errors.Wrapf(err, "error get msp id")
	}

	signer := &CryptoImpl{
		Creator:  name,
		PrivKey:  privateKey,
		SignCert: cert,
	}
	envelope, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_DELIVER_SEEK_INFO,
		channelID,
		signer,
		seekInfo,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed envelope: %v", err)
	}
	return envelope, nil
}

func GetPrivateKey(f string) (*ecdsa.PrivateKey, error) {
	in, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}

	k, err := utils.PEMtoPrivateKey(in, []byte{})
	if err != nil {
		return nil, err
	}

	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf("expecting ecdsa key")
	}

	return key, nil
}

func GetCertificate(f string) (*x509.Certificate, []byte, error) {
	in, err := os.ReadFile(f)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(in)

	c, err := x509.ParseCertificate(block.Bytes)
	return c, in, err
}

func signPayload(payload *common.Payload, privateKey []byte) ([]byte, error) {
	// Implement the signing logic here
	// This is a placeholder and needs to be replaced with actual signing logic
	return []byte("signature"), nil
}

func marshalOrPanic(msg proto.Message) []byte {
	data, err := proto.Marshal(msg)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal protobuf message: %v", err))
	}
	return data
}

type ECDSASignature struct {
	R, S *big.Int
}

type CryptoImpl struct {
	Creator  []byte
	PrivKey  *ecdsa.PrivateKey
	SignCert *x509.Certificate
}

func (s *CryptoImpl) Sign(msg []byte) ([]byte, error) {
	ri, si, err := ecdsa.Sign(rand.Reader, s.PrivKey, digest(msg))
	if err != nil {
		return nil, err
	}

	si, _, err = utils.ToLowS(&s.PrivKey.PublicKey, si)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ECDSASignature{ri, si})
}

func (s *CryptoImpl) Serialize() ([]byte, error) {
	return s.Creator, nil
}

func (s *CryptoImpl) NewSignatureHeader() (*common.SignatureHeader, error) {
	creator, err := s.Serialize()
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.GetRandomNonce()
	if err != nil {
		return nil, err
	}

	return &common.SignatureHeader{
		Creator: creator,
		Nonce:   nonce,
	}, nil
}

func digest(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}
