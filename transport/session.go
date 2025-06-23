package transport

import (
	"bufio"
	"log"
	"sync"
	"time"
)

type Session struct {
	Key      [32]byte
	Role     string
	Writer   *bufio.Writer
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

/*func (sm *SessionManager) SaveWriter(clientID string, w *bufio.Writer) {
	sm.lock.Lock()
	if sess, ok := sm.store[clientID]; ok {
		sess.Writer = w
		sm.store[clientID] = sess
	}
	sm.lock.Unlock()
}*/

func (sm *SessionManager) Load(clientID string) (Session, bool) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	sess, ok := sm.store[clientID]
	if !ok {
		return Session{}, false
	}
	if time.Since(sess.LastSeen) > 5*time.Minute {
		// Session expired
		return Session{}, false
	}
	return sess, true
}

func (sm *SessionManager) StartCleanup(interval time.Duration) {
	go func() {
		for {
			time.Sleep(interval)
			sm.lock.Lock()
			now := time.Now()
			for id, sess := range sm.store {
				if now.Sub(sess.LastSeen) > 5*time.Minute {
					delete(sm.store, id)
					log.Printf("[SessionManager] Cleaned up expired session: %s", id)
				}
			}
			sm.lock.Unlock()
		}
	}()
}
