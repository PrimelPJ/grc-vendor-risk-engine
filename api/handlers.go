// api/handlers.go
//
// HTTP route handlers for the Vendor Risk Assessment API.
// Each handler decodes the request, delegates to the gRPC scoring client,
// persists the result, and returns a structured JSON response.

package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// handler is the dependency container for HTTP route handlers.
type handler struct {
	db      DB
	scoring ScoringClient
}

func newHandler(db DB, scoring ScoringClient) *handler {
	return &handler{db: db, scoring: scoring}
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

type AssessmentRequest struct {
	VendorID    string          `json:"vendor_id"`
	Security    SecurityInput   `json:"security"`
	Privacy     PrivacyInput    `json:"privacy"`
	Resilience  ResilienceInput `json:"resilience"`
	Compliance  ComplianceInput `json:"compliance"`
	Financial   FinancialInput  `json:"financial"`
	SubmittedBy string          `json:"submitted_by,omitempty"`
}

type SecurityInput struct {
	MFAEnforced   bool `json:"mfa_enforced"`
	PenTested     bool `json:"pen_tested"`
	VulnSLADays   int  `json:"vuln_sla_days"`
	SIEMDeployed  bool `json:"siem_deployed"`
	ZeroTrustArch bool `json:"zero_trust_arch"`
}

type PrivacyInput struct {
	NDPACompliant       bool `json:"ndpa_compliant"`
	DPAAppointed        bool `json:"dpa_appointed"`
	CrossBorderTransfers bool `json:"cross_border_transfers"`
	DataMinimization    bool `json:"data_minimization"`
}

type ResilienceInput struct {
	RTOHours int  `json:"rto_hours"`
	RPOHours int  `json:"rpo_hours"`
	DRTested bool `json:"dr_tested"`
}

type ComplianceInput struct {
	ISO27001   bool `json:"iso27001"`
	SOC2Type2  bool `json:"soc2_type2"`
	GDPRAdequate bool `json:"gdpr_adequate"`
}

type FinancialInput struct {
	YearsOperating     int  `json:"years_operating"`
	PublicCompany      bool `json:"public_company"`
	PublicBreachHistory bool `json:"public_breach_history"`
}

type AssessmentResponse struct {
	AssessmentID    string             `json:"assessment_id"`
	VendorID        string             `json:"vendor_id"`
	CompositeScore  float64            `json:"composite_score"`
	RiskBand        string             `json:"risk_band"`
	DimensionScores map[string]float64 `json:"dimension_scores"`
	Failures        map[string][]string `json:"failures"`
	AssessedAt      time.Time          `json:"assessed_at"`
	ReportURL       string             `json:"report_url,omitempty"`
}

// ---------------------------------------------------------------------------
// POST /api/v1/assessments
// ---------------------------------------------------------------------------

func (h *handler) createAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqID := requestIDFromContext(ctx)

	var req AssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if err := validateAssessmentRequest(&req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error(), nil)
		return
	}

	slog.InfoContext(ctx, "Scoring vendor",
		"request_id", reqID,
		"vendor_id", req.VendorID,
	)

	scoreResult, err := h.scoring.ScoreVendor(ctx, req)
	if err != nil {
		slog.ErrorContext(ctx, "Scoring engine error", "error", err, "request_id", reqID)
		writeError(w, http.StatusInternalServerError, "scoring engine unavailable", nil)
		return
	}

	assessmentID := uuid.New().String()
	resp := AssessmentResponse{
		AssessmentID:    assessmentID,
		VendorID:        req.VendorID,
		CompositeScore:  scoreResult.CompositeScore,
		RiskBand:        scoreResult.RiskBand,
		DimensionScores: scoreResult.DimensionScores,
		Failures:        scoreResult.Failures,
		AssessedAt:      time.Now().UTC(),
		ReportURL:       "/api/v1/assessments/" + assessmentID + "/report",
	}

	if err := h.db.InsertAssessment(ctx, resp); err != nil {
		slog.ErrorContext(ctx, "Failed to persist assessment", "error", err)
		// Non-fatal: return result even if DB write fails
	}

	writeJSON(w, http.StatusCreated, resp)
}

// ---------------------------------------------------------------------------
// GET /api/v1/assessments/{id}
// ---------------------------------------------------------------------------

func (h *handler) getAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	if id == "" {
		writeError(w, http.StatusBadRequest, "assessment id is required", nil)
		return
	}

	assessment, err := h.db.GetAssessment(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "assessment not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "database error", nil)
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// ---------------------------------------------------------------------------
// GET /api/v1/vendors/{vendor_id}/history
// ---------------------------------------------------------------------------

func (h *handler) listVendorHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vendorID := r.PathValue("vendor_id")

	history, err := h.db.ListVendorAssessments(ctx, vendorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error", nil)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"vendor_id": vendorID,
		"count":     len(history),
		"records":   history,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func validateAssessmentRequest(req *AssessmentRequest) error {
	if req.VendorID == "" {
		return errors.New("vendor_id is required")
	}
	if req.Resilience.RPOHours > req.Resilience.RTOHours && req.Resilience.RTOHours > 0 {
		return errors.New("rpo_hours cannot exceed rto_hours")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string, err error) {
	body := map[string]string{"error": msg}
	if err != nil {
		slog.Error("Request error", "message", msg, "detail", err.Error())
	}
	writeJSON(w, status, body)
}

var ErrNotFound = errors.New("record not found")

func requestIDFromContext(ctx interface{ Value(any) any }) string {
	if v := ctx.Value("request_id"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
