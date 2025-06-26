package ecdsa

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "net/http/pprof"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/implement"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/require"
)

// testConfig holds configuration for tests
type testConfig struct {
	threshold     int
	participants  []string
	messageToSign []byte
}

// defaultTestConfig returns default test configuration
func defaultTestConfig() testConfig {
	return testConfig{
		threshold:     1,
		participants:  []string{"party1", "party2", "party3"},
		messageToSign: []byte("test"),
	}
}

// setupTestParties creates and initializes test parties
func setupTestParties(t *testing.T, cfg testConfig) []*ECDSAParty {
	parties := make([]*ECDSAParty, len(cfg.participants))
	preParams := make([]*keygen.LocalPreParams, len(cfg.participants))

	// Create parties and load pre-params
	for i, id := range cfg.participants {
		parties[i] = NewECDSAParty(id)
		params, err := loadPreparams(id)
		require.NoError(t, err, "Failed to load pre-params for %s", id)
		preParams[i] = params
	}

	// Initialize parties with senders
	senders := senders(parties)
	for i, party := range parties {
		party.Init(cfg.participants, cfg.threshold, *preParams[i], senders[i])
		go party.NotifyError()
	}

	return parties
}

// cleanupTestParties ensures proper cleanup of test resources
func cleanupTestParties(parties []*ECDSAParty) {
	for _, party := range parties {
		party.Close()
	}
}

func TestECDSAPartyKeygen2Once(t *testing.T) {
	// go func() {
	// 	clog.Println(http.ListenAndServe("localhost:6060", nil))
	// }()
	// log.SetDebugLogging()
	cfg := defaultTestConfig()

	fmt.Println("=== Starting 5 Key Generation Runs (2 at a time) ===")
	totalRuns := 16
	batchSize := 2
	var wg sync.WaitGroup
	results := make([]struct {
		run      int
		duration time.Duration
		pubKey   []byte
		err      error
	}, totalRuns)

	// Run in batches of 2
	for batch := 0; batch < (totalRuns+batchSize-1)/batchSize; batch++ {
		startIdx := batch * batchSize
		endIdx := startIdx + batchSize
		if endIdx > totalRuns {
			endIdx = totalRuns
		}

		fmt.Printf("Starting batch %d: runs %d-%d\n", batch+1, startIdx+1, endIdx)

		// Start batch of key generations concurrently
		for run := startIdx; run < endIdx; run++ {
			wg.Add(1)
			go func(runNum int) {
				defer wg.Done()

				common.Logger.Infof("Starting run %d/%d\n", runNum+1, totalRuns)

				// Setup test parties for this run
				parties := setupTestParties(t, cfg)

				// Test key generation
				shares := keygenAll(parties)

				// Store results
				results[runNum].run = runNum + 1

				if len(shares) != len(cfg.participants) {
					results[runNum].err = fmt.Errorf("expected %d shares, got %d", len(cfg.participants), len(shares))
					return
				}

				// Extract public key for verification
				if len(shares) > 0 {
					var shareData keygen.LocalPartySaveData
					err := json.Unmarshal(shares[cfg.participants[0]], &shareData)
					if err == nil {
						pubKeyBytes, err := ThresholdPK(&shareData)
						if err == nil {
							results[runNum].pubKey = pubKeyBytes
						} else {
							results[runNum].err = err
						}
					} else {
						results[runNum].err = err
					}
				}

				// Cleanup parties for this run
				cleanupTestParties(parties)

			}(run)
		}

		// Wait for current batch to complete before starting next batch
		wg.Wait()
		fmt.Printf("Batch %d completed\n", batch+1)
	}
	// Print results summary
	fmt.Println("\n=== Key Generation Results ===")
	for _, result := range results {
		if result.err != nil {
			fmt.Printf("Run %d: ERROR - %v\n", result.run, result.err)
		} else {
			fmt.Printf("Run %d: Public Key: %x (completed in %v)\n", result.run, result.pubKey, result.duration)
		}
	}

	fmt.Printf("\n=== All %d Key Generation Runs Completed ===\n", totalRuns)
}

func testResharing(t *testing.T, oldParties []*ECDSAParty, cfg testConfig) []*ECDSAParty {
	// Create new parties for resharing
	newParticipants := []string{"party1-reshare", "party2-reshare", "party3-reshare"}
	newParties := make([]*ECDSAParty, len(newParticipants))

	for i, id := range newParticipants {
		newParties[i] = NewECDSAParty(id)
	}

	// Combine old and new parties for resharing
	allParties := append(oldParties, newParties...)
	reshareSenders := senderForReshare(allParties)

	// Initialize resharing for all parties
	for i, party := range allParties {
		preParams, err := loadPreparams(party.PartyID.Id)
		require.NoError(t, err, "Failed to load pre-params for %s", party.PartyID.Id)

		party.InitReshare(
			cfg.participants,
			newParticipants,
			cfg.threshold,
			1, // new threshold
			*preParams,
			reshareSenders[i],
		)
		go party.NotifyError()
	}

	// Perform resharing
	reshareShares := reshareAll(allParties)
	require.Equal(t, len(allParties), len(reshareShares), "Expected %d reshare shares, got %d", len(allParties), len(reshareShares))
	t.Log("Resharing completed successfully")

	// Remove last party of new parties
	newParties = newParties[:len(newParties)-1]
	newParticipants = newParticipants[:len(newParticipants)-1]
	// Initialize new parties for signing
	newSignSenders := senders(newParties)
	for i, party := range newParties {
		preParams, err := loadPreparams(party.PartyID.Id)
		require.NoError(t, err, "Failed to load pre-params for %s", party.PartyID.Id)

		party.Init(newParticipants, 1, *preParams, newSignSenders[i])
		party.SetShareData(reshareShares[party.PartyID.Id])
	}

	// Test signing with new parties
	sigs := signAll(newParties, cfg.messageToSign)
	require.Equal(t, len(newParticipants), len(sigs), "Expected %d signatures from new parties, got %d", len(newParticipants), len(sigs))
	t.Log("Signing with new parties completed successfully")

	return newParties
}

func keygenAll(parties []*ECDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *ECDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					common.Logger.Errorf("Party %s panicked: %v", p.PartyID.Id, r)
				}
			}()

			p.Keygen(func(share *keygen.LocalPartySaveData) {
				bz, err := json.Marshal(share)
				if err != nil {
					common.Logger.Errorf("Party %s failed to marshal share data: %v", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				shares[p.PartyID.Id] = bz
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return shares
}

func signAll(parties []*ECDSAParty, msg []byte) [][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	sigs := make([][]byte, 0, len(parties))
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *ECDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					common.Logger.Errorf("Party %s panicked: %v", p.PartyID.Id, r)
				}
			}()

			p.Sign(msg, func(sig *common.SignatureData) {
				bz, err := json.Marshal(sig)
				if err != nil {
					common.Logger.Errorf("Party %s failed to marshal signature: %v", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				sigs = append(sigs, bz)
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return sigs
}

func reshareAll(parties []*ECDSAParty) map[string][]byte {
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	shares := make(map[string][]byte)
	var mu sync.Mutex

	for _, party := range parties {
		go func(p *ECDSAParty) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					common.Logger.Errorf("Party %s panicked: %v", p.PartyID.Id, r)
				}
			}()

			p.Reshare(func(share *keygen.LocalPartySaveData) {
				bz, err := json.Marshal(share)
				if err != nil {
					common.Logger.Errorf("Party %s failed to marshal share data: %v", p.PartyID.Id, err)
					return
				}
				mu.Lock()
				shares[p.PartyID.Id] = bz
				mu.Unlock()
			})
		}(party)
	}
	wg.Wait()
	return shares
}

func senders(parties []*ECDSAParty) []implement.Sender {
	senders := make([]implement.Sender, len(parties))
	for i, src := range parties {
		src := src
		senders[i] = func(msg tss.Message) {
			msgBytes, _, err := msg.WireBytes()
			if err != nil {
				common.Logger.Errorf("Party %s failed to get wire bytes: %v", src.PartyID.Id, err)
				return
			}
			round, isBroadcast, err := ClassifyMsg(msgBytes)
			if err != nil {
				common.Logger.Errorf("Party %s failed to classify message: %v", src.PartyID.Id, err)
				return
			}
			common.Logger.Infof("Party %s received message, round: %d, isBroadcast: %t", src.PartyID.Id, round, isBroadcast)
			if isBroadcast {
				for _, dst := range parties {
					if dst.PartyID.Id != src.PartyID.Id {
						dst.OnMsg(msg)
					}
				}
			} else {
				to := msg.GetTo()
				if to == nil {
					common.Logger.Errorf("Warning: Party %s message has nil recipients", src.PartyID.Id)
					return
				}
				for _, recipient := range to {
					for _, dst := range parties {
						if recipient.Id == dst.PartyID.Id {
							dst.OnMsg(msg)
							break
						}
					}
				}
			}
		}
	}
	return senders
}

func senderForReshare(parties []*ECDSAParty) []implement.Sender {
	senders := make([]implement.Sender, len(parties))
	for i, src := range parties {
		src := src
		senders[i] = func(msg tss.Message) {
			msgBytes, _, err := msg.WireBytes()
			if err != nil {
				common.Logger.Errorf("Party %s failed to get wire bytes: %v", src.PartyID.Id, err)
				return
			}
			round, isBroadcast, err := ClassifyMsg(msgBytes)
			if err != nil {
				common.Logger.Errorf("Party %s failed to classify message: %v", src.PartyID.Id, err)
				return
			}
			common.Logger.Infof("Party %s received message, round: %d, isBroadcast: %t", src.PartyID.Id, round, isBroadcast)

			to := msg.GetTo()
			if to == nil {
				common.Logger.Errorf("Warning: Party %s message has nil recipients", src.PartyID.Id)
				return
			}
			for _, recipient := range to {
				for _, dst := range parties {
					if recipient.Id == dst.PartyID.Id {
						dst.OnMsg(msg)
						break
					}
				}
			}
		}
	}
	return senders
}

func loadPreparams(partyID string) (*keygen.LocalPreParams, error) {
	// Try to read existing file
	data, err := os.ReadFile("preparams_" + partyID + ".json")
	if err == nil {
		var params *keygen.LocalPreParams
		if err := json.Unmarshal(data, &params); err == nil {
			return params, nil
		}
	}

	// Generate new parameters
	params, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		return nil, err
	}

	// Save the new parameters
	if data, err := json.Marshal(params); err == nil {
		os.WriteFile("preparams_"+partyID+".json", data, 0644)
	}

	return params, nil
}

func ThresholdPK(shareData *keygen.LocalPartySaveData) ([]byte, error) {
	if shareData == nil {
		return nil, fmt.Errorf("must call SetShareData() before attempting to sign")
	}

	pk := shareData.ECDSAPub
	ecdsaPK := &ecdsa.PublicKey{
		Curve: shareData.ECDSAPub.Curve(),
		X:     pk.X(),
		Y:     pk.Y(),
	}

	return encodeS256PubKey(ecdsaPK)
}

func encodeS256PubKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	publicKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return publicKeyBytes, nil
}
