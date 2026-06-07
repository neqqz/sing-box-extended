package inbound

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/ssh"
	CM "github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing-box/service/node/constant"
)

type SSHManager struct {
	inbounds map[string]*SSHUserManager

	mtx sync.Mutex
}

func NewSSHManager() *SSHManager {
	return &SSHManager{
		inbounds: make(map[string]*SSHUserManager),
	}
}

func (m *SSHManager) AddUserManager(inbound adapter.Inbound) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.inbounds[inbound.Tag()] = &SSHUserManager{
		inbound:  inbound.(*ssh.Inbound),
		usersMap: make(map[string]option.SSHUser),
	}
	return nil
}

func (m *SSHManager) GetUserManager(tag string) (constant.UserManager, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	inbound, ok := m.inbounds[tag]
	return inbound, ok
}

func (m *SSHManager) GetUserManagerTags() []string {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	tags := make([]string, 0, len(m.inbounds))
	for tag := range m.inbounds {
		tags = append(tags, tag)
	}
	return tags
}

type SSHUserManager struct {
	inbound  *ssh.Inbound
	usersMap map[string]option.SSHUser

	mtx sync.Mutex
}

func (i *SSHUserManager) postUpdate() {
	users := make([]option.SSHUser, 0, len(i.usersMap))
	for _, user := range i.usersMap {
		users = append(users, user)
	}
	i.inbound.UpdateUsers(users)
}

func convertSSHUser(user CM.User) option.SSHUser {
	return option.SSHUser{
		Name:           user.Username,
		Password:       user.Password,
		AuthorizedKeys: user.AuthorizedKeys,
	}
}

func (i *SSHUserManager) UpdateUser(user CM.User) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	i.usersMap[user.Username] = convertSSHUser(user)
	i.postUpdate()
}

func (i *SSHUserManager) UpdateUsers(users []CM.User) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	clear(i.usersMap)
	for _, user := range users {
		i.usersMap[user.Username] = convertSSHUser(user)
	}
	i.postUpdate()
}

func (i *SSHUserManager) DeleteUser(username string) {
	i.mtx.Lock()
	defer i.mtx.Unlock()
	delete(i.usersMap, username)
	i.postUpdate()
}
