package engine

// scorer accumulates rule matches and computes the anomaly score. Unlike
// plain CRS, it scores per label (per argument), so one long legit value
// that trips three notice rules totals 2, not 6, while an attack sprayed
// across arguments still adds up. scoringSum falls back to pure CRS.
type scorer struct {
	sum        bool
	byLabel    map[string]*labelScore
	evidence   []Evidence
	forceBlock bool
	forceAllow bool
	challenge  bool
}

type labelScore struct {
	// highest score seen per category on this label
	byCat  map[string]int
	notice int
}

func newScorer(sum bool) *scorer {
	return &scorer{sum: sum, byLabel: map[string]*labelScore{}}
}

func (s *scorer) add(r *Rule, label string, ev Evidence) {
	s.evidence = append(s.evidence, ev)
	switch r.Action {
	case ActBlock:
		s.forceBlock = true
		return
	case ActAllow:
		s.forceAllow = true
		return
	case ActChallenge:
		s.challenge = true
		return
	case ActLog:
		return
	}
	ls := s.byLabel[label]
	if ls == nil {
		ls = &labelScore{byCat: map[string]int{}}
		s.byLabel[label] = ls
	}
	if r.Severity == SevNotice {
		ls.notice += r.Score
		return
	}
	if r.Score > ls.byCat[r.Category] {
		ls.byCat[r.Category] = r.Score
	}
}

// total computes the request score and the label that contributed most.
func (s *scorer) total() (int, string) {
	if s.sum {
		sum := 0
		for _, ls := range s.byLabel {
			for _, v := range ls.byCat {
				sum += v
			}
			sum += ls.notice
		}
		return sum, s.topLabel()
	}
	best, secondaries := 0, 0
	top := ""
	perLabel := map[string]int{}
	for label, ls := range s.byLabel {
		t := 0
		for _, v := range ls.byCat {
			t += v
		}
		// notice contributions on a label are capped at 2 total
		n := ls.notice
		if n > 2 {
			n = 2
		}
		t += n
		perLabel[label] = t
		if t > best {
			best, top = t, label
		}
	}
	for label, t := range perLabel {
		if label != top && t >= 3 {
			secondaries++
		}
	}
	if secondaries > 3 {
		secondaries = 3
	}
	return best + secondaries, top
}

func (s *scorer) topLabel() string {
	top, best := "", -1
	for label, ls := range s.byLabel {
		t := ls.notice
		for _, v := range ls.byCat {
			t += v
		}
		if t > best {
			best, top = t, label
		}
	}
	return top
}
