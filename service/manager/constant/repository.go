package constant

type Repository interface {
	CreateSquad(user SquadCreate) (Squad, error)
	GetSquads(filters map[string][]string) ([]Squad, error)
	GetSquadsCount(filters map[string][]string) (int, error)
	GetSquad(id int) (Squad, error)
	UpdateSquad(id int, user SquadUpdate) (Squad, error)
	DeleteSquad(id int) (DeletedSquad, error)

	CreateNode(node NodeCreate) (Node, error)
	GetNodes(filters map[string][]string) ([]Node, error)
	GetNodesCount(filters map[string][]string) (int, error)
	GetNode(uuid string) (Node, error)
	UpdateNode(uuid string, node NodeUpdate) (Node, error)
	DeleteNode(uuid string) (Node, error)

	CreateUser(user UserCreate) (User, error)
	GetUsers(filters map[string][]string) ([]User, error)
	GetUsersCount(filters map[string][]string) (int, error)
	GetUser(id int) (User, error)
	UpdateUser(id int, user UserUpdate) (User, error)
	DeleteUser(id int) (User, error)

	CreateConnectionLimiter(limiter ConnectionLimiterCreate) (ConnectionLimiter, error)
	GetConnectionLimiters(filters map[string][]string) ([]ConnectionLimiter, error)
	GetConnectionLimitersCount(filters map[string][]string) (int, error)
	GetConnectionLimiter(id int) (ConnectionLimiter, error)
	UpdateConnectionLimiter(id int, limiter ConnectionLimiterUpdate) (ConnectionLimiter, error)
	DeleteConnectionLimiter(id int) (ConnectionLimiter, error)

	CreateBandwidthLimiter(limiter BandwidthLimiterCreate) (BandwidthLimiter, error)
	GetBandwidthLimiters(filters map[string][]string) ([]BandwidthLimiter, error)
	GetBandwidthLimitersCount(filters map[string][]string) (int, error)
	GetBandwidthLimiter(id int) (BandwidthLimiter, error)
	UpdateBandwidthLimiter(id int, limiter BandwidthLimiterUpdate) (BandwidthLimiter, error)
	DeleteBandwidthLimiter(id int) (BandwidthLimiter, error)

	CreateTrafficLimiter(limiter TrafficLimiterCreate) (TrafficLimiter, error)
	GetTrafficLimiters(filters map[string][]string) ([]TrafficLimiter, error)
	GetTrafficLimitersCount(filters map[string][]string) (int, error)
	GetTrafficLimiter(id int) (TrafficLimiter, error)
	UpdateTrafficLimiter(id int, limiter TrafficLimiterUpdate) (TrafficLimiter, error)
	UpdateTrafficLimiterUsed(id int, used uint64) (TrafficLimiter, error)
	DeleteTrafficLimiter(id int) (TrafficLimiter, error)

	CreateRateLimiter(limiter RateLimiterCreate) (RateLimiter, error)
	GetRateLimiters(filters map[string][]string) ([]RateLimiter, error)
	GetRateLimitersCount(filters map[string][]string) (int, error)
	GetRateLimiter(id int) (RateLimiter, error)
	UpdateRateLimiter(id int, limiter RateLimiterUpdate) (RateLimiter, error)
	DeleteRateLimiter(id int) (RateLimiter, error)
}
