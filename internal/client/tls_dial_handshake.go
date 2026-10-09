package client

import (
	"context"
	"net"

	"github.com/ameshkov/gocurl/internal/client/utlsengine"
	"github.com/ameshkov/gocurl/internal/config"
	utls "github.com/refraction-networking/utls"
)

type tlsDialObservation struct {
	profileCheckEnabled bool
	reportingEnabled    bool
	connectionID        string
	leg                 string
	attempt             int
}

func (d *clientDialer) newTLSObservation(ctx context.Context) tlsDialObservation {
	leg := tlsLegFromContext(ctx)
	profileCheckEnabled := d.cfg.TLSProfileCheck
	proxyProfileCheckEnabled := d.cfg.ProxyTLSProfileCheck || d.cfg.ProxyTLSProfileStrict
	reportingEnabled := profileCheckEnabled || proxyProfileCheckEnabled || d.cfg.OutputJSON
	connectionID := ""
	attempt := 0
	if reportingEnabled {
		attempt = utlsengine.BeginProfileCheckAttempt(ctx)
		connectionID = utlsengine.NewConnectionID()
	}

	return tlsDialObservation{
		profileCheckEnabled: profileCheckEnabled,
		reportingEnabled:    reportingEnabled,
		connectionID:        connectionID,
		leg:                 leg,
		attempt:             attempt,
	}
}

func (d *clientDialer) reportTLSOpenFailure(
	ctx context.Context,
	conn net.Conn,
	err error,
	observation tlsDialObservation,
) error {
	profileCheckEnabled, reportingEnabled := observation.profileCheckEnabled, observation.reportingEnabled
	connectionID, leg, attempt := observation.connectionID, observation.leg, observation.attempt
	if conn != nil {
		_ = conn.Close()
	}
	if reportingEnabled {
		var profileDocument utlsengine.ClientProfile
		if d.cfg.TLSProfileDocument != nil {
			profileDocument = *d.cfg.TLSProfileDocument
		}
		check := utlsengine.ProfileCheckResult{Status: "NOT_OBSERVED", Error: err.Error()}
		if d.cfg.TLSProfileDocument != nil {
			check.Expected = d.cfg.TLSProfileDocument.Expected
		}
		utlsengine.RecordProfileCheck(ctx, utlsengine.NewConnectionReportForLeg(
			profileDocument, check, connectionID, leg, attempt, 1,
		))
		if profileCheckEnabled {
			d.logProfileCheck(check)
		}
	}
	if profileCheckEnabled {
		return utlsengine.NewProfileCheckError("CONNECTION_ERROR", err)
	}
	return err
}

func (d *clientDialer) handshakeDialedTLS(
	ctx context.Context,
	conn net.Conn,
	observation tlsDialObservation,
) (net.Conn, int, error) {
	if d.tlsProfile != nil {
		return d.handshakeProfiledTLS(ctx, conn, observation)
	}
	_, postQuantum := d.cfg.Experiments[config.ExpPostQuantum]
	if d.cfg.ECH || d.cfg.ECHGrease || postQuantum {
		return d.handshakeExperimentalTLS(ctx, conn, observation)
	}
	return d.handshakeObservedStandardTLS(ctx, conn, observation)
}

func (d *clientDialer) handshakeProfiledTLS(
	ctx context.Context,
	conn net.Conn,
	observation tlsDialObservation,
) (tlsConn net.Conn, helloCount int, err error) {
	var capture *utlsengine.CaptureConn
	profile := *d.tlsProfile
	if len(profile.ALPN) == 0 && (d.cfg.ForceHTTP11 || d.cfg.ForceHTTP2) {
		profile.ALPN = append([]string(nil), d.tlsConfig.NextProtos...)
	}
	utlsConfig := &utls.Config{
		ServerName:         d.tlsConfig.ServerName,
		MinVersion:         d.tlsConfig.MinVersion,
		MaxVersion:         d.tlsConfig.MaxVersion,
		CipherSuites:       d.tlsConfig.CipherSuites,
		InsecureSkipVerify: d.tlsConfig.InsecureSkipVerify,
		Rand:               d.tlsConfig.Rand,
		NextProtos:         append([]string(nil), d.tlsConfig.NextProtos...),
	}
	var profileConn *utls.UConn
	profileConn, capture, err = utlsengine.Handshake(ctx, conn, utlsConfig, profile)
	if profileConn != nil {
		tlsConn = profileConn
	}
	err = connectionPhaseError(ctx, err)
	if capture != nil {
		helloCount = capture.ClientHelloCount()
	}
	err = d.checkProfiledTLSHandshake(ctx, tlsConn, capture, err, observation)
	return tlsConn, helloCount, err
}

func (d *clientDialer) checkProfiledTLSHandshake(
	ctx context.Context,
	tlsConn net.Conn,
	capture *utlsengine.CaptureConn,
	err error,
	observation tlsDialObservation,
) error {
	profileCheckEnabled, reportingEnabled := observation.profileCheckEnabled, observation.reportingEnabled
	connectionID, leg, attempt := observation.connectionID, observation.leg, observation.attempt
	var checks []utlsengine.ProfileCheckResult
	profileDocument := utlsengine.ClientProfile{}
	if d.cfg.TLSProfileDocument != nil {
		profileDocument = *d.cfg.TLSProfileDocument
	}
	if profileCheckEnabled && d.cfg.TLSProfileDocument != nil {
		checks, _ = utlsengine.CaptureProfileChecks(profileDocument, capture)
	} else if profileCheckEnabled {
		checks = []utlsengine.ProfileCheckResult{
			{Status: "UNSUPPORTED", Error: "TLS profile expectations are unavailable"},
		}
	} else if reportingEnabled {
		checks = utlsengine.CaptureObservations(capture)
	}
	if reportingEnabled {
		if err != nil {
			for i := range checks {
				if checks[i].Error == "" {
					checks[i].Error = err.Error()
				}
			}
		}
		strictFailure := d.recordConnectionChecksForLeg(
			ctx, profileDocument, checks, connectionID, leg, attempt, profileCheckEnabled,
		)
		if err != nil {
			if profileCheckEnabled {
				if strictFailure == "INCOMPLETE" {
					return utlsengine.NewProfileCheckError(strictFailure, err)
				}
				return utlsengine.NewProfileCheckError("CONNECTION_ERROR", err)
			}
			return err
		}
		if d.cfg.TLSProfileStrict && strictFailure != "" {
			if tlsConn != nil {
				_ = tlsConn.Close()
			}
			d.setConn(nil)
			return utlsengine.NewProfileCheckError(strictFailure, nil)
		}
	}
	return err
}

func (d *clientDialer) handshakeExperimentalTLS(
	ctx context.Context,
	conn net.Conn,
	observation tlsDialObservation,
) (tlsConn net.Conn, helloCount int, err error) {
	profileCheckEnabled, reportingEnabled := observation.profileCheckEnabled, observation.reportingEnabled
	connectionID, leg, attempt := observation.connectionID, observation.leg, observation.attempt
	tlsConn, err = d.handshakeCTLS(ctx, conn)
	err = connectionPhaseError(ctx, err)
	if reportingEnabled {
		check := utlsengine.ProfileCheckResult{
			Status: "NOT_OBSERVED",
			Error:  "ClientHello capture is not available for this TLS engine",
		}
		if err != nil {
			check.Status = "CONNECTION_ERROR"
			check.Error = err.Error()
		}
		strictFailure := d.recordConnectionChecksForLeg(
			ctx,
			utlsengine.ClientProfile{},
			[]utlsengine.ProfileCheckResult{check},
			connectionID,
			leg,
			attempt,
			profileCheckEnabled,
		)
		if strictErr := rejectStrictProfileCheck(
			tlsConn,
			d.cfg.TLSProfileStrict,
			strictFailure,
		); strictErr != nil {
			if tlsConn == nil && conn != nil {
				_ = conn.Close()
			}
			d.setConn(nil)
			return nil, 0, strictErr
		}
	}
	return tlsConn, 0, err
}

func (d *clientDialer) handshakeObservedStandardTLS(
	ctx context.Context,
	conn net.Conn,
	observation tlsDialObservation,
) (tlsConn net.Conn, helloCount int, err error) {
	var capture *utlsengine.CaptureConn
	profileCheckEnabled, reportingEnabled := observation.profileCheckEnabled, observation.reportingEnabled
	connectionID, leg, attempt := observation.connectionID, observation.leg, observation.attempt
	if reportingEnabled {
		capture = &utlsengine.CaptureConn{Conn: conn}
		tlsConn, err = d.handshakeTLS(capture)
		err = connectionPhaseError(ctx, err)
		capture.StopCapture()
		helloCount = capture.ClientHelloCount()
		checks := utlsengine.CaptureObservations(capture)
		if err != nil {
			for i := range checks {
				if checks[i].Error == "" {
					checks[i].Error = err.Error()
				}
			}
		}
		d.recordConnectionChecksForLeg(
			ctx, utlsengine.ClientProfile{}, checks, connectionID, leg, attempt, profileCheckEnabled,
		)
	} else {
		tlsConn, err = d.handshakeTLS(conn)
		err = connectionPhaseError(ctx, err)
	}
	return tlsConn, helloCount, err
}
