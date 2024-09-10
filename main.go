package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/exzz/netatmo-api-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/xperimental/netatmo-exporter/v2/internal/collector"
	"github.com/xperimental/netatmo-exporter/v2/internal/config"
	"github.com/xperimental/netatmo-exporter/v2/internal/logger"
	"github.com/xperimental/netatmo-exporter/v2/internal/token"
	"github.com/xperimental/netatmo-exporter/v2/internal/web"
	"golang.org/x/oauth2"
)

var (
	signals = []os.Signal{
		syscall.SIGINT,
		syscall.SIGTERM,
	}

	log = logger.NewLogger()
)

func main() {
	cfg, err := config.Parse(os.Args, os.Getenv)
	switch {
	case err == pflag.ErrHelp:
		return
	case err != nil:
		log.Fatalf("Error in configuration: %s", err)
	default:
	}
	log.SetLevel(logrus.Level(cfg.LogLevel))

	var tok *oauth2.Token
	if cfg.TokenFile == "" {
		log.Warn("No token-file set! Authentication will be lost on restart.")
	} else {
		tok, err = loadToken(cfg.TokenFile)
		switch {
		case os.IsNotExist(err):
		case err != nil:
			log.Fatalf("Error loading token: %s", err)

		default:
			if tok.RefreshToken == "" {
				log.Warn("Restored token has no refresh-token! Exporter will need to be re-authenticated manually.")
			} else if tok.Expiry.IsZero() {
				log.Warn("Restored token has no expiry time! Token will be renewed immediately.")
				tok.Expiry = time.Now().Add(time.Second)
			}
			log.Infof("Loaded token from %s.", cfg.TokenFile)
		}
	}

	client := netatmo.NewClient(netatmo.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenSource:  newFileTokenSource(cfg.TokenFile, tok),
	})
	if tok != nil {
		client.InitWithToken(context.Background(), tok)
	}

	metrics := collector.New(log, client.Read, cfg.RefreshInterval, cfg.StaleDuration)
	prometheus.MustRegister(metrics)

	tokenMetric := token.Metric(client.CurrentToken)
	prometheus.MustRegister(tokenMetric)

	if cfg.DebugHandlers {
		http.Handle("/debug/data", web.DebugDataHandler(log, client.Read))
		http.Handle("/debug/token", web.DebugTokenHandler(log, client.CurrentToken))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.Handle("/auth/authorize", web.AuthorizeHandler(cfg.ExternalURL, client))
	http.Handle("/auth/callback", web.CallbackHandler(ctx, client))
	http.Handle("/auth/settoken", web.SetTokenHandler(ctx, client))
	http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))
	http.Handle("/version", versionHandler(log))
	http.Handle("/", web.HomeHandler(client.CurrentToken))

	log.Infof("Listen on %s...", cfg.Addr)
	log.Fatal(http.ListenAndServe(cfg.Addr, nil))
}

func loadToken(fileName string) (*oauth2.Token, error) {
	if fileName == "" {
		return nil, nil
	}
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var token oauth2.Token
	if err := json.NewDecoder(file).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

// newFileTokenSource returns a wrapper for a TokenSource that saves to tokenFile.
//
// If initialToken is non-nil, that particular token is not saved.
func newFileTokenSource(tokenFile string, initialToken *oauth2.Token) func(oauth2.TokenSource) oauth2.TokenSource {
	if tokenFile == "" {
		log.Info("OOK no token file")
		return nil
	}
	var initialExpiry time.Time
	if initialToken != nil {
		initialExpiry = initialToken.Expiry
	}
	return func(source oauth2.TokenSource) oauth2.TokenSource {
		return &fileTokenSource{
			source:     source,
			tokenFile:  tokenFile,
			lastExpiry: initialExpiry,
		}
	}
}

// fileTokenSource detects when the token changes and saves it.
type fileTokenSource struct {
	// Original TokenSource
	source oauth2.TokenSource
	// File to update when the token is refreshed
	tokenFile string
	// Expiry value of the last token that was seen
	lastExpiry time.Time
}

func (f *fileTokenSource) Token() (*oauth2.Token, error) {
	token, err := f.source.Token()
	if err != nil {
		log.Infof("OOK Token() failed %s", err)
		return token, err
	}
	log.Infof("OOK got Token() %s/%s", token.Expiry, f.lastExpiry)

	if token.Expiry != f.lastExpiry {
		// Token was refreshed, save it. A failure here shouldn't
		// disrupt normal operations.
		f.lastExpiry = token.Expiry

		log.Infof("Token refreshed. Saving to %s ...", f.tokenFile)
		data, err := json.Marshal(token)
		if err != nil {
			log.Warnf("Error marshalling token: %s", err)
		} else {
			if err = os.WriteFile(f.tokenFile, data, 0o600); err != nil {
				log.Warnf("Error writing token file %s: %s", f.tokenFile, err)
			}
		}
	}
	return token, nil
}
