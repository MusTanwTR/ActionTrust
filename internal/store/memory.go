package store

import (
	"sync"

	"actiontrust/internal/models"
)

type MemoryStore struct {
	mu            sync.RWMutex
	latest        *models.AssessmentResponse
	latestDataset *models.DatasetAssessmentReport
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (s *MemoryStore) SaveLatest(r models.AssessmentResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := r
	s.latest = &copy
}

func (s *MemoryStore) Latest() (models.AssessmentResponse, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latest == nil {
		return models.AssessmentResponse{}, false
	}
	return *s.latest, true
}

func (s *MemoryStore) SaveLatestDataset(r models.DatasetAssessmentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := r
	s.latestDataset = &copy
}

func (s *MemoryStore) LatestDataset() (models.DatasetAssessmentReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latestDataset == nil {
		return models.DatasetAssessmentReport{}, false
	}
	return *s.latestDataset, true
}
