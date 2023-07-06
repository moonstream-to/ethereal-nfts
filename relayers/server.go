package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	RELAYERS_CORS_ALLOWED_ORIGINS = os.Getenv("RELAYERS_CORS_ALLOWED_ORIGINS")

	ACTIVE_RELAYER_TYPE = ""
)

// corsMiddleware handles CORS origin check
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if RELAYERS_CORS_ALLOWED_ORIGINS == "" {
			log.Println("missed CORS origins environment variable")
		}
		if r.Method == http.MethodOptions {
			for _, allowedOrigin := range strings.Split(RELAYERS_CORS_ALLOWED_ORIGINS, ",") {
				if r.Header.Get("Origin") == allowedOrigin {
					w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
					w.Header().Set("Access-Control-Allow-Methods", "GET,POST")
					// Credentials are cookies, authorization headers, or TLS client certificates
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// logMiddleware parse log access requests in proper format
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Unable to read body", http.StatusBadRequest)
			return
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		if len(body) > 0 {
			defer r.Body.Close()
		}

		next.ServeHTTP(w, r)

		var ip string
		realIp := r.Header["X-Real-Ip"]
		if len(realIp) == 0 {
			ip, _, err = net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, fmt.Sprintf("Unable to parse client IP: %s", r.RemoteAddr), http.StatusBadRequest)
				return
			}
		} else {
			ip = realIp[0]
		}
		logStr := fmt.Sprintf("relayer-%s %s %s - %s", ACTIVE_RELAYER_TYPE, ip, r.Method, r.URL.Path)

		log.Printf("%s\n", logStr)
	})
}

// panicMiddleware handles panic errors to prevent server shutdown
func panicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Println("recovered panic error", err)
				http.Error(w, "Internal server error", 500)
			}
		}()

		// There will be a defer with panic handler in each next function
		next.ServeHTTP(w, r)
	})
}

// pingHandler response with status of load balancer server itself
func PingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := PingResponse{Status: "ok"}
	json.NewEncoder(w).Encode(response)
}

func RunServer(relayerType, serverHost string, serverPort int) error {
	var server *http.Server
	var relayer Relayer

	switch relayerType {
	case "erc721":
		relayer = &ERC721Relayer{}
	default:
		return fmt.Errorf("unknown relayer type: %s", relayerType)
	}
	ACTIVE_RELAYER_TYPE = relayerType

	relayerConfigurationErr := relayer.ConfigureFromEnv()
	if relayerConfigurationErr != nil {
		return fmt.Errorf("failed to configure relayer, err: %v", relayerConfigurationErr)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", PingHandler)
	mux.HandleFunc("/status", relayer.StatusHandler)
	mux.HandleFunc("/address", relayer.AddressHandler)
	mux.HandleFunc("/validate", relayer.ValidateHandler)
	mux.HandleFunc("/create_message_hash", relayer.CreateMessageHashHandler)
	mux.HandleFunc("/authorize", relayer.AuthorizeHandler)

	// Set middleware, from bottom to top
	commonHandler := corsMiddleware(mux)
	commonHandler = logMiddleware(commonHandler)
	commonHandler = panicMiddleware(commonHandler)

	server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", serverHost, serverPort),
		Handler:      commonHandler,
		ReadTimeout:  40 * time.Second,
		WriteTimeout: 40 * time.Second,
	}

	log.Printf("Starting %s relayer server on: %s:%d", relayerType, serverHost, serverPort)
	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server listener, err: %v", err)
	}

	return nil
}
