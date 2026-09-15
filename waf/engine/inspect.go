package engine

import (
	"net/http"
	"time"
)

// Inspect evaluates a request through the request phases and returns a
// verdict. A nil engine (or disabled) allows everything. The request body
// is only buffered when a body-phase rule could fire and the method can
// carry one, so a plain GET never pays for a body read.
func (e *Engine) Inspect(r *http.Request) *Verdict {
	if e == nil || !e.cfg.Enabled {
		return &Verdict{Action: ActAllow, Effective: ActAllow}
	}
	rs := e.cur.Load()
	if rs == nil {
		return &Verdict{Action: ActAllow, Effective: ActAllow}
	}
	start := time.Now()
	pol := e.resolve(r.Host, r.URL.Path, r.Method)

	tx := e.txPool.Get().(*Tx)
	defer e.recycle(tx)
	tx.reset(e.limits())

	if r.Context().Err() != nil {
		return &Verdict{Action: ActAllow, Effective: ActAllow, Aborted: true}
	}

	// phase 1: headers, path, query. block here before any body read.
	tx.collectRequestHead(r)
	sc := rs.evaluate(tx, pol, PhaseReqHeaders)
	if v := e.finish(sc, pol, PhaseReqHeaders, start, rs.hash); v != nil {
		return v
	}

	// phase 2: body, but only if the ruleset has body rules and the request
	// carries one.
	if len(rs.byPhase[PhaseReqBody]) > 0 && r.Context().Err() == nil {
		tx.collectRequestBody(r, e.limits().MaxInspect, e.cfg.BodyOverLimit)
		if tx.bodySkip == "truncated" && e.cfg.BodyOverLimit == "block" {
			return e.blockVerdict(pol, PhaseReqBody, start, rs.hash, "body over inspect limit")
		}
		sc2 := rs.evaluate(tx, pol, PhaseReqBody)
		mergeScorer(sc, sc2)
	}
	v := e.settle(sc, pol, PhaseReqBody, start, rs.hash, tx.bodySkip)
	return v
}

// InspectResponse runs the response phases over what the backend returned.
func (e *Engine) InspectResponse(r *http.Request, status int, header http.Header, bodyData []byte) *Verdict {
	if e == nil || !e.cfg.Enabled || e.cfg.Response.Mode == "off" || e.cfg.Response.Mode == "" {
		return &Verdict{Action: ActAllow, Effective: ActAllow}
	}
	rs := e.cur.Load()
	if rs == nil {
		return &Verdict{Action: ActAllow, Effective: ActAllow}
	}
	start := time.Now()
	pol := e.resolve(r.Host, r.URL.Path, r.Method)
	if e.cfg.Response.Mode == "detect" {
		pol.mode = ModeDetect
	}
	pol.threshold = pol.respThreshold

	tx := e.txPool.Get().(*Tx)
	defer e.recycle(tx)
	tx.reset(e.limits())
	tx.collectResponse(status, header, bodyData)

	sc := rs.evaluate(tx, pol, PhaseRespHeaders)
	sc2 := rs.evaluate(tx, pol, PhaseRespBody)
	mergeScorer(sc, sc2)
	return e.settle(sc, pol, PhaseRespBody, start, rs.hash, "")
}

// finish returns a verdict when the scorer already forces one (block/allow/
// challenge from an action rule), else nil to keep going.
func (e *Engine) finish(sc *scorer, pol *policy, phase Phase, start time.Time, hash string) *Verdict {
	if sc.forceAllow {
		return e.mkVerdict(sc, pol, phase, start, hash, ActAllow, "")
	}
	if sc.forceBlock && pol.mode != ModeDetect {
		return e.mkVerdict(sc, pol, phase, start, hash, ActBlock, "")
	}
	if sc.challenge && pol.mode != ModeDetect {
		return e.mkVerdict(sc, pol, phase, start, hash, ActChallenge, "")
	}
	return nil
}

// settle computes the final verdict from the accumulated score.
func (e *Engine) settle(sc *scorer, pol *policy, phase Phase, start time.Time, hash, bodySkip string) *Verdict {
	if sc.forceAllow {
		return e.mkVerdict(sc, pol, phase, start, hash, ActAllow, bodySkip)
	}
	score, top := sc.total()
	want := ActScore
	if sc.forceBlock {
		want = ActBlock
	} else if sc.challenge {
		want = ActChallenge
	} else if score >= pol.threshold {
		want = ActBlock
	}
	v := e.mkVerdictScored(sc, pol, phase, start, hash, want, bodySkip, score, top)
	return v
}

func (e *Engine) blockVerdict(pol *policy, phase Phase, start time.Time, hash, reason string) *Verdict {
	v := &Verdict{
		Action: ActBlock, Effective: ActBlock, Threshold: pol.threshold,
		Paranoia: int(pol.paranoia), Mode: pol.mode.String(), Phase: phase,
		Duration: time.Since(start), Ruleset: hash, BodySkip: reason,
	}
	if pol.mode == ModeDetect {
		v.Effective = ActAllow
	}
	return v
}

func (e *Engine) mkVerdict(sc *scorer, pol *policy, phase Phase, start time.Time, hash string, action Action, bodySkip string) *Verdict {
	score, top := sc.total()
	return e.mkVerdictScored(sc, pol, phase, start, hash, action, bodySkip, score, top)
}

func (e *Engine) mkVerdictScored(sc *scorer, pol *policy, phase Phase, start time.Time, hash string, action Action, bodySkip string, score int, top string) *Verdict {
	v := &Verdict{
		Action: action, Effective: action, Score: score, Threshold: pol.threshold,
		Paranoia: int(pol.paranoia), Mode: pol.mode.String(), TopLabel: top,
		Evidence: sc.evidence, Phase: phase, Duration: time.Since(start),
		Ruleset: hash, BodySkip: bodySkip,
	}
	// detect mode never blocks or challenges, but keeps the evidence
	if pol.mode == ModeDetect && (action == ActBlock || action == ActChallenge) {
		v.Effective = ActAllow
	}
	if action == ActScore {
		v.Effective = ActAllow
	}
	v.trimExplain(e.cfg.ExplainOnBlock)
	v.sortEvidence()
	e.stats.total.Add(uint64(len(sc.evidence)))
	return v
}

// trimExplain drops evidence detail per the explain_on_block setting.
func (v *Verdict) trimExplain(level string) {
	switch level {
	case "none":
		v.Evidence = nil
	case "full":
		// keep everything
	default: // "rules": keep ids and targets, drop match windows
		for i := range v.Evidence {
			v.Evidence[i].Match = ""
			v.Evidence[i].Window = ""
		}
	}
}

func mergeScorer(dst, src *scorer) {
	dst.evidence = append(dst.evidence, src.evidence...)
	if src.forceBlock {
		dst.forceBlock = true
	}
	if src.forceAllow {
		dst.forceAllow = true
	}
	if src.challenge {
		dst.challenge = true
	}
	for label, ls := range src.byLabel {
		d := dst.byLabel[label]
		if d == nil {
			dst.byLabel[label] = ls
			continue
		}
		d.notice += ls.notice
		for cat, v := range ls.byCat {
			if v > d.byCat[cat] {
				d.byCat[cat] = v
			}
		}
	}
}

func (e *Engine) recycle(tx *Tx) {
	if tx.cache.Grown(1 << 20) {
		return // drop oversized caches instead of pinning memory
	}
	e.txPool.Put(tx)
}

// LogEvent sends a decision to the sink. Callers pass request metadata since
// the engine does not keep the request.
func (e *Engine) LogEvent(v *Verdict, requestID, ip, host, method, reqPath string) {
	sh := e.sink.Load()
	if sh == nil {
		return
	}
	action := v.Effective.String()
	if v.Effective == ActAllow && v.Action == ActBlock {
		action = "detect"
	}
	if v.Effective == ActAllow && len(v.Evidence) == 0 && !e.cfg.LogAllowed {
		return
	}
	sh.s.Log(Event{
		Time: time.Now(), RequestID: requestID, IP: ip, Host: host,
		Method: method, Path: reqPath, Action: action, Mode: v.Mode,
		Score: v.Score, Threshold: v.Threshold, Paranoia: v.Paranoia,
		TopLabel: v.TopLabel, Phase: v.Phase.String(), Ruleset: v.Ruleset,
		Evidence: v.Evidence,
	})
}
