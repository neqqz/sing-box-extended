package option

type ManagerServiceDatabase struct {
	Driver string `json:"driver"`
	DSN    string `json:"dsn"`
}

type ManagerServiceOptions struct {
	Inbounds []string               `json:"inbounds"`
	Database ManagerServiceDatabase `json:"database"`
}
