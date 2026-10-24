package inbound

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/trusttunnel"
	CM "github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing-box/service/node/constant"
)

type TrustTunnelManager struct {
	inbounds map[string]*TrustTunnelUserManager

	mtx sync.Mutex
}

func NewTrustTunnelManager() *TrustTunnelManager {
	return &TrustTunnelManager{
		inbounds: make(map[string]*TrustTunnelUserManager),
	}
}

func (m *TrustTunnelManager) AddUserManager(inbound adapter.Inbound) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	inb := inbound.(*trusttunnel.Inbound)
	userMgr := &TrustTunnelUserManager{
		inbound:  inb,
		usersMap: make(map[string]option.TrustTunnelUser),
	}
	for _, u := range inb.Options().Users {
		userMgr.usersMap[u.Name] = u
	}
	m.inbounds[inbound.Tag()] = userMgr
	return nil
}

func (m *TrustTunnelManager) GetUserManager(tag string) (constant.UserManager, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	inbound, ok := m.inbounds[tag]
	return inbound, ok
}

func (m *TrustTunnelManager) GetUserManagerTags() []string {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	tags := make([]string, 0, len(m.inbounds))
	for tag := range m.inbounds {
		tags = append(tags, tag)
	}
	return tags
}

type TrustTunnelUserManager struct {
	inbound  *trusttunnel.Inbound
	usersMap map[string]option.TrustTunnelUser

	mtx sync.Mutex
}

func (i *TrustTunnelUserManager) postUpdate() {
	users := make([]option.TrustTunnelUser, 0, len(i.usersMap))
	for _, user := range i.usersMap {
		users = append(users, user)
	}
	i.inbound.UpdateUsers(users)
}

func (i *TrustTunnelUserManager) UpdateUser(user CM.User) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	i.usersMap[user.Username] = option.TrustTunnelUser{Name: user.Username, Password: user.Password}
	i.postUpdate()
}

func (i *TrustTunnelUserManager) UpdateUsers(users []CM.User) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	clear(i.usersMap)
	for _, user := range users {
		i.usersMap[user.Username] = option.TrustTunnelUser{Name: user.Username, Password: user.Password}
	}
	i.postUpdate()
}

func (i *TrustTunnelUserManager) DeleteUser(username string) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	delete(i.usersMap, username)
	i.postUpdate()
}
