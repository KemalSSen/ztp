package transport

import (
	"sync"
	"time"
)

type Session struct {
	Key      [32]byte
	Role     string
	LastSeen time.Time
}

type SessionManager struct {
	store map[string]Session
	lock  sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		store: make(map[string]Session),
	}
}

func (sm *SessionManager) Save(clientID string, sess Session) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	sess.LastSeen = time.Now()
	sm.store[clientID] = sess
}

func (sm *SessionManager) Load(clientID string) (Session, bool) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	sess, ok := sm.store[clientID]
	if !ok {
		return Session{}, false
	}
	if time.Since(sess.LastSeen) > 10*time.Minute {
		// Session expired
		return Session{}, false
	}
	return sess, true
}
