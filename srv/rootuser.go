package srv

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type UserStore struct {
	users map[string]*userInfo
	mu sync.RWMutex
}

func newUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*userInfo, 1),
	}
}

func (s *UserStore) Set(id string, u *userInfo) {
	s.mu.Lock()
	s.users[id] = u
	s.mu.Unlock()
}

func (s *UserStore) Get(id string) (*userInfo, bool) {
	s.mu.RLock()
	u, ok := s.users[id]
	s.mu.RUnlock()
	return u, ok
}

func (s *UserStore) Persist() error {
	f, err := os.OpenFile("user.yaml", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open user.yaml failed: %w", err)
	}

	defer f.Close()

	s.mu.RLock()
	err = yaml.NewEncoder(f).Encode(s.users)
	s.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("encode user.yaml failed: %w", err)
	}

	return nil
}

func (s *UserStore) Load() error {
	f, err := os.Open("user.yaml")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		
		return fmt.Errorf("open user.yaml failed: %w", err)
	}

	defer f.Close()

	s.mu.Lock()
	err = yaml.NewDecoder(f).Decode(&s.users)
	s.mu.Unlock()

	if err != nil {
		return fmt.Errorf("decode user.yaml failed: %w", err)
	}

	return nil
}
