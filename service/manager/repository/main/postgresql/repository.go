package postgresql

import (
	"context"
	dbsql "database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/huandu/go-sqlbuilder"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sagernet/sing-box/common/sql"
	"github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing/common/byteformats"
)

var squadFilters, nodeFilters, userFilters, bandwidthLimiterFilters, connectionLimiterFilters, trafficLimiterFilters, rateLimiterFilters map[string]sql.Filter

type PostgreSQLRepository struct {
	db  *pgxpool.Pool
	ctx context.Context
}

func NewPostgreSQLRepository(ctx context.Context, dsn string) (*PostgreSQLRepository, error) {
	db, err := dbsql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := Migrate(db); err != nil && err != migrate.ErrNoChange {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &PostgreSQLRepository{db: pool, ctx: ctx}, nil
}

func notFoundErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return constant.ErrNotFound
	}
	return err
}

func (r *PostgreSQLRepository) CreateSquad(squad constant.SquadCreate) (constant.Squad, error) {
	var s constant.Squad
	now := time.Now()
	err := r.db.QueryRow(
		r.ctx, `
		INSERT INTO squads
		(
			name,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3)
		RETURNING
			id,
			name,
			created_at,
			updated_at
	`,
		squad.Name,
		now,
		now,
	).Scan(
		&s.ID,
		&s.Name,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	return s, err
}

func (r *PostgreSQLRepository) GetSquads(filters map[string][]string) ([]constant.Squad, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select(
			"id",
			"name",
			"created_at",
			"updated_at",
		).
		From("squads")
	for k, v := range filters {
		if f, ok := squadFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return nil, err
			}
		}
	}
	query, args := sb.Build()
	rows, err := r.db.Query(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.Squad
	for rows.Next() {
		var squad constant.Squad
		if err := rows.Scan(
			&squad.ID,
			&squad.Name,
			&squad.CreatedAt,
			&squad.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, squad)
	}
	return result, rows.Err()
}

func (r *PostgreSQLRepository) GetSquadsCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select("COUNT(*)").
		From("squads")
	for k, v := range filters {
		if f, ok := squadFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return 0, err
			}
		}
	}
	query, args := sb.Build()
	var count int
	err := r.db.QueryRow(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) GetSquad(id int) (constant.Squad, error) {
	var s constant.Squad
	err := r.db.QueryRow(r.ctx, `
		SELECT
			id,
			name,
			created_at,
			updated_at
		FROM squads
		WHERE id=$1
	`, id).Scan(
		&s.ID,
		&s.Name,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	return s, notFoundErr(err)
}

func (r *PostgreSQLRepository) UpdateSquad(id int, squad constant.SquadUpdate) (constant.Squad, error) {
	var s constant.Squad
	err := r.db.QueryRow(
		r.ctx, `
		UPDATE squads
		SET
			name=$1,
			updated_at=$2
		WHERE id=$3
		RETURNING
			id,
			name,
			created_at,
			updated_at
	`,
		squad.Name,
		time.Now(),
		id,
	).Scan(
		&s.ID,
		&s.Name,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	return s, err
}

func (r *PostgreSQLRepository) DeleteSquad(id int) (constant.DeletedSquad, error) {
	var result constant.DeletedSquad
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(r.ctx)
	affectedNodeRows, err := tx.Query(r.ctx, `DELETE FROM node_to_squad WHERE squad_id=$1 RETURNING node_uuid`, id)
	if err != nil {
		return result, err
	}
	affectedNodeUUIDs := make([]string, 0)
	for affectedNodeRows.Next() {
		var uuid string
		if err = affectedNodeRows.Scan(&uuid); err != nil {
			affectedNodeRows.Close()
			return result, err
		}
		affectedNodeUUIDs = append(affectedNodeUUIDs, uuid)
	}
	affectedNodeRows.Close()
	if err = affectedNodeRows.Err(); err != nil {
		return result, err
	}
	for _, table := range []string{
		"user_to_squad",
		"connection_limiter_to_squad",
		"bandwidth_limiter_to_squad",
		"traffic_limiter_to_squad",
		"rate_limiter_to_squad",
	} {
		if _, err = tx.Exec(r.ctx, `DELETE FROM `+table+` WHERE squad_id=$1`, id); err != nil {
			return result, err
		}
	}
	err = tx.QueryRow(r.ctx, `
		DELETE FROM squads
		WHERE id=$1
		RETURNING
			id,
			name,
			created_at,
			updated_at
	`, id).Scan(
		&result.Squad.ID,
		&result.Squad.Name,
		&result.Squad.CreatedAt,
		&result.Squad.UpdatedAt,
	)
	if err != nil {
		return result, err
	}
	orphanedNodeRows, err := tx.Query(r.ctx, `
		DELETE FROM nodes
		WHERE NOT EXISTS (SELECT 1 FROM node_to_squad WHERE node_to_squad.node_uuid = nodes.uuid)
		RETURNING uuid
	`)
	if err != nil {
		return result, err
	}
	orphanedNodeUUIDs := make(map[string]struct{})
	for orphanedNodeRows.Next() {
		var uuid string
		if err = orphanedNodeRows.Scan(&uuid); err != nil {
			orphanedNodeRows.Close()
			return result, err
		}
		orphanedNodeUUIDs[uuid] = struct{}{}
		result.OrphanedNodeUUIDs = append(result.OrphanedNodeUUIDs, uuid)
	}
	orphanedNodeRows.Close()
	if err = orphanedNodeRows.Err(); err != nil {
		return result, err
	}
	for _, uuid := range affectedNodeUUIDs {
		if _, ok := orphanedNodeUUIDs[uuid]; !ok {
			result.SurvivingNodeUUIDs = append(result.SurvivingNodeUUIDs, uuid)
		}
	}
	if _, err = tx.Exec(r.ctx, `
		DELETE FROM users
		WHERE NOT EXISTS (SELECT 1 FROM user_to_squad WHERE user_to_squad.user_id = users.id)
	`); err != nil {
		return result, err
	}
	connRows, err := tx.Query(r.ctx, `
		DELETE FROM connection_limiters
		WHERE NOT EXISTS (SELECT 1 FROM connection_limiter_to_squad WHERE connection_limiter_to_squad.connection_limiter_id = connection_limiters.id)
		RETURNING id
	`)
	if err != nil {
		return result, err
	}
	for connRows.Next() {
		var lid int
		if err = connRows.Scan(&lid); err != nil {
			connRows.Close()
			return result, err
		}
		result.OrphanedConnectionLimiterIDs = append(result.OrphanedConnectionLimiterIDs, lid)
	}
	connRows.Close()
	if err = connRows.Err(); err != nil {
		return result, err
	}
	if _, err = tx.Exec(r.ctx, `
		DELETE FROM bandwidth_limiters
		WHERE NOT EXISTS (SELECT 1 FROM bandwidth_limiter_to_squad WHERE bandwidth_limiter_to_squad.bandwidth_limiter_id = bandwidth_limiters.id)
	`); err != nil {
		return result, err
	}
	trafficRows, err := tx.Query(r.ctx, `
		DELETE FROM traffic_limiters
		WHERE NOT EXISTS (SELECT 1 FROM traffic_limiter_to_squad WHERE traffic_limiter_to_squad.traffic_limiter_id = traffic_limiters.id)
		RETURNING id
	`)
	if err != nil {
		return result, err
	}
	for trafficRows.Next() {
		var lid int
		if err = trafficRows.Scan(&lid); err != nil {
			trafficRows.Close()
			return result, err
		}
		result.OrphanedTrafficLimiterIDs = append(result.OrphanedTrafficLimiterIDs, lid)
	}
	trafficRows.Close()
	if err = trafficRows.Err(); err != nil {
		return result, err
	}
	if _, err = tx.Exec(r.ctx, `
		DELETE FROM rate_limiters
		WHERE NOT EXISTS (SELECT 1 FROM rate_limiter_to_squad WHERE rate_limiter_to_squad.rate_limiter_id = rate_limiters.id)
	`); err != nil {
		return result, err
	}
	if err = tx.Commit(r.ctx); err != nil {
		return result, err
	}
	return result, nil
}

func (r *PostgreSQLRepository) CreateNode(node constant.NodeCreate) (constant.Node, error) {
	var n constant.Node
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return n, err
	}
	defer tx.Rollback(r.ctx)
	now := time.Now()
	err = tx.QueryRow(
		r.ctx, `
		INSERT INTO nodes (
			uuid,
			name,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4)
		RETURNING 
			uuid,
			name,
			created_at,
			updated_at
	`,
		node.UUID,
		node.Name,
		now,
		now,
	).Scan(
		&n.UUID,
		&n.Name,
		&n.CreatedAt,
		&n.UpdatedAt,
	)
	if err != nil {
		return n, err
	}
	rows := make([][]any, len(node.SquadIDs))
	for i, squadID := range node.SquadIDs {
		rows[i] = []any{node.UUID, squadID}
	}
	_, err = tx.CopyFrom(
		r.ctx,
		pgx.Identifier{"node_to_squad"},
		[]string{"node_uuid", "squad_id"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return n, err
	}
	err = tx.Commit(r.ctx)
	if err != nil {
		return n, err
	}
	return n, err
}

func (r *PostgreSQLRepository) GetNodes(filters map[string][]string) ([]constant.Node, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select(
			"uuid",
			"name",
			`ARRAY(
				SELECT squad_id
				FROM node_to_squad
				WHERE node_to_squad.node_uuid = nodes.uuid
			) as squad_ids`,
			"created_at",
			"updated_at",
		).
		From("nodes")
	for key, value := range filters {
		if filter, ok := nodeFilters[key]; ok {
			if err := filter(sb, value); err != nil {
				return nil, err
			}
		}
	}
	query, args := sb.Build()
	rows, err := r.db.Query(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.Node
	for rows.Next() {
		var n constant.Node
		if err := rows.Scan(
			&n.UUID,
			&n.Name,
			&n.SquadIDs,
			&n.CreatedAt,
			&n.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, rows.Err()
}

func (r *PostgreSQLRepository) GetNodesCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select("COUNT(*)").
		From("nodes")
	for key, value := range filters {
		if filter, ok := nodeFilters[key]; ok {
			if err := filter(sb, value); err != nil {
				return 0, err
			}
		}
	}
	query, args := sb.Build()
	var count int
	err := r.db.QueryRow(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) GetNode(uuid string) (constant.Node, error) {
	var n constant.Node
	err := r.db.QueryRow(r.ctx, `
		SELECT 
			uuid,
			name, 
			ARRAY(
				SELECT squad_id
				FROM node_to_squad
				WHERE node_to_squad.node_uuid = nodes.uuid
			) as squad_ids,
			created_at,
			updated_at
		FROM nodes
		WHERE uuid = $1
	`, uuid).Scan(
		&n.UUID,
		&n.Name,
		&n.SquadIDs,
		&n.CreatedAt,
		&n.UpdatedAt,
	)
	return n, notFoundErr(err)
}

func (r *PostgreSQLRepository) UpdateNode(uuid string, node constant.NodeUpdate) (constant.Node, error) {
	var n constant.Node
	err := r.db.QueryRow(
		r.ctx, `
		UPDATE nodes
		SET 
			name = $1,
			updated_at = $2
		WHERE uuid = $3
		RETURNING
			uuid,
			name,
			created_at,
			updated_at
	`,
		node.Name,
		time.Now(),
		uuid,
	).Scan(
		&n.UUID,
		&n.Name,
		&n.CreatedAt,
		&n.UpdatedAt,
	)
	return n, err
}

func (r *PostgreSQLRepository) DeleteNode(uuid string) (constant.Node, error) {
	var n constant.Node
	err := r.db.QueryRow(r.ctx, `
		DELETE FROM nodes
		WHERE uuid = $1
		RETURNING 
			uuid,
			name,
			created_at,
			updated_at
	`, uuid).Scan(
		&n.UUID,
		&n.Name,
		&n.CreatedAt,
		&n.UpdatedAt,
	)
	return n, err
}

func (r *PostgreSQLRepository) CreateUser(user constant.UserCreate) (constant.User, error) {
	var u constant.User
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return u, err
	}
	defer tx.Rollback(r.ctx)
	now := time.Now()
	authorizedKeysJSON, err := marshalStringSlice(user.AuthorizedKeys)
	if err != nil {
		return u, err
	}
	var authorizedKeys sql.SliceJSON[string]
	err = tx.QueryRow(
		r.ctx, `
		INSERT INTO users (
			username,
			inbound,
			type,
			uuid,
			password,
			secret,
			authorized_keys,
			flow,
			alter_id,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING 
			id,
			username,
			inbound,
			type,
			uuid,
			password,
			secret,
			authorized_keys,
			flow,
			alter_id,
			created_at,
			updated_at
	`,
		user.Username,
		user.Inbound,
		user.Type,
		user.UUID,
		user.Password,
		user.Secret,
		authorizedKeysJSON,
		user.Flow,
		user.AlterID,
		now,
		now,
	).Scan(
		&u.ID,
		&u.Username,
		&u.Inbound,
		&u.Type,
		&u.UUID,
		&u.Password,
		&u.Secret,
		&authorizedKeys,
		&u.Flow,
		&u.AlterID,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		return u, err
	}
	u.AuthorizedKeys = []string(authorizedKeys)
	rows := make([][]any, len(user.SquadIDs))
	for i, squadID := range user.SquadIDs {
		rows[i] = []any{u.ID, squadID}
	}
	_, err = tx.CopyFrom(
		r.ctx,
		pgx.Identifier{"user_to_squad"},
		[]string{"user_id", "squad_id"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return u, err
	}
	u.SquadIDs = user.SquadIDs
	err = tx.Commit(r.ctx)
	if err != nil {
		return u, err
	}
	return u, err
}

func (r *PostgreSQLRepository) GetUsers(filters map[string][]string) ([]constant.User, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select(
			"id",
			`ARRAY(
				SELECT squad_id
				FROM user_to_squad
				WHERE user_to_squad.user_id = users.id
			) as squad_ids`,
			"username",
			"inbound",
			"type",
			"uuid",
			"password",
			"secret",
			"authorized_keys",
			"flow",
			"alter_id",
			"created_at",
			"updated_at",
		).
		From("users")
	for key, value := range filters {
		if filter, ok := userFilters[key]; ok {
			if err := filter(sb, value); err != nil {
				return nil, err
			}
		}
	}
	query, args := sb.Build()
	rows, err := r.db.Query(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.User
	for rows.Next() {
		var u constant.User
		if err := rows.Scan(
			&u.ID,
			&u.SquadIDs,
			&u.Username,
			&u.Inbound,
			&u.Type,
			&u.UUID,
			&u.Password,
			&u.Secret,
			&u.AuthorizedKeys,
			&u.Flow,
			&u.AlterID,
			&u.CreatedAt,
			&u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (r *PostgreSQLRepository) GetUsersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select("COUNT(*)").
		From("users")
	for key, value := range filters {
		if filter, ok := userFilters[key]; ok {
			if err := filter(sb, value); err != nil {
				return 0, err
			}
		}
	}
	query, args := sb.Build()
	var count int
	err := r.db.QueryRow(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) GetUser(id int) (constant.User, error) {
	var u constant.User
	err := r.db.QueryRow(r.ctx, `
		SELECT
			id,
			ARRAY(
				SELECT squad_id
				FROM user_to_squad
				WHERE user_to_squad.user_id = users.id
			) as squad_ids,
			username,
			inbound,
			type,
			uuid,
			password,
			secret,
			authorized_keys,
			flow,
			alter_id,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`, id).Scan(
		&u.ID,
		&u.SquadIDs,
		&u.Username,
		&u.Inbound,
		&u.Type,
		&u.UUID,
		&u.Password,
		&u.Secret,
		&u.AuthorizedKeys,
		&u.Flow,
		&u.AlterID,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	return u, notFoundErr(err)
}

func (r *PostgreSQLRepository) UpdateUser(id int, user constant.UserUpdate) (constant.User, error) {
	var u constant.User
	authorizedKeysJSON, err := marshalStringSlice(user.AuthorizedKeys)
	if err != nil {
		return u, err
	}
	err = r.db.QueryRow(
		r.ctx, `
		UPDATE users
		SET
			uuid = $1,
			password = $2,
			secret = $3,
			authorized_keys = $4,
			flow = $5,
			alter_id = $6,
			updated_at = $7
		WHERE id = $8
		RETURNING
			id,
			ARRAY(
				SELECT squad_id
				FROM user_to_squad
				WHERE user_to_squad.user_id = users.id
			) as squad_ids,
			username,
			inbound,
			type,
			uuid,
			password,
			secret,
			authorized_keys,
			flow,
			alter_id,
			created_at,
			updated_at
	`,
		user.UUID,
		user.Password,
		user.Secret,
		authorizedKeysJSON,
		user.Flow,
		user.AlterID,
		time.Now(),
		id,
	).Scan(
		&u.ID,
		&u.SquadIDs,
		&u.Username,
		&u.Inbound,
		&u.Type,
		&u.UUID,
		&u.Password,
		&u.Secret,
		&u.AuthorizedKeys,
		&u.Flow,
		&u.AlterID,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	return u, err
}

func (r *PostgreSQLRepository) DeleteUser(id int) (constant.User, error) {
	var u constant.User
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return u, err
	}
	defer tx.Rollback(r.ctx)
	var squadIDs []int
	squadRows, err := tx.Query(r.ctx, `SELECT squad_id FROM user_to_squad WHERE user_id = $1`, id)
	if err != nil {
		return u, err
	}
	for squadRows.Next() {
		var squadID int
		if err = squadRows.Scan(&squadID); err != nil {
			squadRows.Close()
			return u, err
		}
		squadIDs = append(squadIDs, squadID)
	}
	squadRows.Close()
	if err = squadRows.Err(); err != nil {
		return u, err
	}
	err = tx.QueryRow(r.ctx, `
		DELETE FROM users
		WHERE id = $1
		RETURNING
			id,
			username,
			inbound,
			type,
			uuid,
			password,
			secret,
			authorized_keys,
			flow,
			alter_id,
			created_at,
			updated_at
	`, id).Scan(
		&u.ID,
		&u.Username,
		&u.Inbound,
		&u.Type,
		&u.UUID,
		&u.Password,
		&u.Secret,
		&u.AuthorizedKeys,
		&u.Flow,
		&u.AlterID,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		return u, err
	}
	u.SquadIDs = squadIDs
	return u, tx.Commit(r.ctx)
}

func (r *PostgreSQLRepository) CreateConnectionLimiter(limiter constant.ConnectionLimiterCreate) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return cl, err
	}
	defer tx.Rollback(r.ctx)
	now := time.Now()
	err = tx.QueryRow(
		r.ctx, `
		INSERT INTO connection_limiters
		(
			username,
			outbound,
			strategy,
			connection_type,
			lock_type,
			count,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING
			id,
			username,
			outbound,
			strategy,
			connection_type,
			lock_type,
			count,
			created_at,
			updated_at
	`,
		limiter.Username,
		limiter.Outbound,
		limiter.Strategy,
		limiter.ConnectionType,
		limiter.LockType,
		limiter.Count,
		now,
		now,
	).Scan(
		&cl.ID,
		&cl.Username,
		&cl.Outbound,
		&cl.Strategy,
		&cl.ConnectionType,
		&cl.LockType,
		&cl.Count,
		&cl.CreatedAt,
		&cl.UpdatedAt,
	)
	if err != nil {
		return cl, err
	}
	rows := make([][]any, len(limiter.SquadIDs))
	for i, squadID := range limiter.SquadIDs {
		rows[i] = []any{cl.ID, squadID}
	}
	_, err = tx.CopyFrom(
		r.ctx,
		pgx.Identifier{"connection_limiter_to_squad"},
		[]string{"connection_limiter_id", "squad_id"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return cl, err
	}
	cl.SquadIDs = limiter.SquadIDs
	err = tx.Commit(r.ctx)
	if err != nil {
		return cl, err
	}
	return cl, err
}

func (r *PostgreSQLRepository) GetConnectionLimiters(filters map[string][]string) ([]constant.ConnectionLimiter, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select(
			"id",
			`ARRAY(
				SELECT squad_id
				FROM connection_limiter_to_squad
				WHERE connection_limiter_to_squad.connection_limiter_id = connection_limiters.id
			) as squad_ids`,
			"username",
			"outbound",
			"strategy",
			"connection_type",
			"lock_type",
			"count",
			"created_at",
			"updated_at",
		).
		From("connection_limiters")
	for k, v := range filters {
		if f, ok := connectionLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return nil, err
			}
		}
	}
	query, args := sb.Build()
	rows, err := r.db.Query(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.ConnectionLimiter
	for rows.Next() {
		var cl constant.ConnectionLimiter
		if err := rows.Scan(
			&cl.ID,
			&cl.SquadIDs,
			&cl.Username,
			&cl.Outbound,
			&cl.Strategy,
			&cl.ConnectionType,
			&cl.LockType,
			&cl.Count,
			&cl.CreatedAt,
			&cl.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, cl)
	}

	return result, rows.Err()
}

func (r *PostgreSQLRepository) GetConnectionLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select("COUNT(*)").
		From("connection_limiters")

	for k, v := range filters {
		if f, ok := connectionLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return 0, err
			}
		}
	}
	query, args := sb.Build()
	var count int
	err := r.db.QueryRow(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) GetConnectionLimiter(id int) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	err := r.db.QueryRow(r.ctx, `
		SELECT
			id,
			ARRAY(
				SELECT squad_id
				FROM connection_limiter_to_squad
				WHERE connection_limiter_to_squad.connection_limiter_id = connection_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			connection_type,
			lock_type,
			count,
			created_at,
			updated_at
		FROM connection_limiters
		WHERE id=$1
	`, id).Scan(
		&cl.ID,
		&cl.SquadIDs,
		&cl.Username,
		&cl.Outbound,
		&cl.Strategy,
		&cl.ConnectionType,
		&cl.LockType,
		&cl.Count,
		&cl.CreatedAt,
		&cl.UpdatedAt,
	)
	return cl, notFoundErr(err)
}

func (r *PostgreSQLRepository) UpdateConnectionLimiter(id int, limiter constant.ConnectionLimiterUpdate) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	err := r.db.QueryRow(
		r.ctx, `
		UPDATE connection_limiters
		SET
			strategy=$1,
			connection_type=$2,
			lock_type=$3,
			count=$4,
			updated_at=$5
		WHERE id=$6
		RETURNING
			id,
			ARRAY(
				SELECT squad_id
				FROM connection_limiter_to_squad
				WHERE connection_limiter_to_squad.connection_limiter_id = connection_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			connection_type,
			lock_type,
			count,
			created_at,
			updated_at
	`,
		limiter.Strategy,
		limiter.ConnectionType,
		limiter.LockType,
		limiter.Count,
		time.Now(),
		id,
	).Scan(
		&cl.ID,
		&cl.SquadIDs,
		&cl.Username,
		&cl.Outbound,
		&cl.Strategy,
		&cl.ConnectionType,
		&cl.LockType,
		&cl.Count,
		&cl.CreatedAt,
		&cl.UpdatedAt,
	)
	return cl, err
}

func (r *PostgreSQLRepository) DeleteConnectionLimiter(id int) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return cl, err
	}
	defer tx.Rollback(r.ctx)
	var squadIDs []int
	squadRows, err := tx.Query(r.ctx, `SELECT squad_id FROM connection_limiter_to_squad WHERE connection_limiter_id = $1`, id)
	if err != nil {
		return cl, err
	}
	for squadRows.Next() {
		var squadID int
		if err = squadRows.Scan(&squadID); err != nil {
			squadRows.Close()
			return cl, err
		}
		squadIDs = append(squadIDs, squadID)
	}
	squadRows.Close()
	if err = squadRows.Err(); err != nil {
		return cl, err
	}
	err = tx.QueryRow(r.ctx, `
		DELETE FROM connection_limiters
		WHERE id=$1
		RETURNING
			id,
			username,
			outbound,
			strategy,
			connection_type,
			lock_type,
			count,
			created_at,
			updated_at
	`, id).Scan(
		&cl.ID,
		&cl.Username,
		&cl.Outbound,
		&cl.Strategy,
		&cl.ConnectionType,
		&cl.LockType,
		&cl.Count,
		&cl.CreatedAt,
		&cl.UpdatedAt,
	)
	if err != nil {
		return cl, err
	}
	cl.SquadIDs = squadIDs
	return cl, tx.Commit(r.ctx)
}

func (r *PostgreSQLRepository) CreateBandwidthLimiter(limiter constant.BandwidthLimiterCreate) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return bl, err
	}
	defer tx.Rollback(r.ctx)
	bytesSpeed, err := json.Marshal(limiter.Speed)
	if err != nil {
		return bl, err
	}
	raw := &byteformats.NetworkBytesCompat{}
	if err = raw.UnmarshalJSON(bytesSpeed); err != nil {
		return bl, err
	}
	flowKeysJSON, err := marshalStringSlice(limiter.FlowKeys)
	if err != nil {
		return bl, err
	}
	var flowKeys sql.SliceJSON[string]
	now := time.Now()
	err = tx.QueryRow(
		r.ctx, `
		INSERT INTO bandwidth_limiters
		(
			username,
			outbound,
			strategy,
			connection_type,
			mode,
			flow_keys,
			speed,
			raw_speed,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING
			id,
			username,
			outbound,
			strategy,
			connection_type,
			mode,
			flow_keys,
			speed,
			raw_speed,
			created_at,
			updated_at
	`,
		limiter.Username,
		limiter.Outbound,
		limiter.Strategy,
		limiter.ConnectionType,
		limiter.Mode,
		flowKeysJSON,
		limiter.Speed,
		raw.Value(),
		now,
		now,
	).Scan(
		&bl.ID,
		&bl.Username,
		&bl.Outbound,
		&bl.Strategy,
		&bl.ConnectionType,
		&bl.Mode,
		&flowKeys,
		&bl.Speed,
		&bl.RawSpeed,
		&bl.CreatedAt,
		&bl.UpdatedAt,
	)
	if err != nil {
		return bl, err
	}
	bl.FlowKeys = []string(flowKeys)
	rows := make([][]any, len(limiter.SquadIDs))
	for i, squadID := range limiter.SquadIDs {
		rows[i] = []any{bl.ID, squadID}
	}
	_, err = tx.CopyFrom(
		r.ctx,
		pgx.Identifier{"bandwidth_limiter_to_squad"},
		[]string{"bandwidth_limiter_id", "squad_id"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return bl, err
	}
	bl.SquadIDs = limiter.SquadIDs
	err = tx.Commit(r.ctx)
	if err != nil {
		return bl, err
	}
	return bl, err
}

func (r *PostgreSQLRepository) GetBandwidthLimiters(filters map[string][]string) ([]constant.BandwidthLimiter, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select(
			"id",
			`ARRAY(
				SELECT squad_id
				FROM bandwidth_limiter_to_squad
				WHERE bandwidth_limiter_to_squad.bandwidth_limiter_id = bandwidth_limiters.id
			) as squad_ids`,
			"username",
			"outbound",
			"strategy",
			"connection_type",
			"mode",
			"flow_keys",
			"speed",
			"raw_speed",
			"created_at",
			"updated_at",
		).
		From("bandwidth_limiters")

	for k, v := range filters {
		if f, ok := bandwidthLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return nil, err
			}
		}
	}
	query, args := sb.Build()
	rows, err := r.db.Query(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.BandwidthLimiter
	for rows.Next() {
		var bl constant.BandwidthLimiter
		var flowKeys sql.SliceJSON[string]
		if err := rows.Scan(
			&bl.ID,
			&bl.SquadIDs,
			&bl.Username,
			&bl.Outbound,
			&bl.Strategy,
			&bl.ConnectionType,
			&bl.Mode,
			&flowKeys,
			&bl.Speed,
			&bl.RawSpeed,
			&bl.CreatedAt,
			&bl.UpdatedAt,
		); err != nil {
			return nil, err
		}
		bl.FlowKeys = []string(flowKeys)
		result = append(result, bl)
	}
	return result, rows.Err()
}

func (r *PostgreSQLRepository) GetBandwidthLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select("COUNT(*)").
		From("bandwidth_limiters")
	for k, v := range filters {
		if f, ok := bandwidthLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return 0, err
			}
		}
	}
	query, args := sb.Build()
	var count int
	err := r.db.QueryRow(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) GetBandwidthLimiter(id int) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	var flowKeys sql.SliceJSON[string]
	err := r.db.QueryRow(r.ctx, `
		SELECT
			id,
			ARRAY(
				SELECT squad_id
				FROM bandwidth_limiter_to_squad
				WHERE bandwidth_limiter_to_squad.bandwidth_limiter_id = bandwidth_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			connection_type,
			mode,
			flow_keys,
			speed,
			raw_speed,
			created_at,
			updated_at
		FROM bandwidth_limiters
		WHERE id=$1
	`, id).Scan(
		&bl.ID,
		&bl.SquadIDs,
		&bl.Username,
		&bl.Outbound,
		&bl.Strategy,
		&bl.ConnectionType,
		&bl.Mode,
		&flowKeys,
		&bl.Speed,
		&bl.RawSpeed,
		&bl.CreatedAt,
		&bl.UpdatedAt,
	)
	bl.FlowKeys = []string(flowKeys)
	return bl, notFoundErr(err)
}

func (r *PostgreSQLRepository) UpdateBandwidthLimiter(id int, limiter constant.BandwidthLimiterUpdate) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	var flowKeys sql.SliceJSON[string]
	bytesSpeed, err := json.Marshal(limiter.Speed)
	if err != nil {
		return bl, err
	}
	raw := &byteformats.NetworkBytesCompat{}
	if err = raw.UnmarshalJSON(bytesSpeed); err != nil {
		return bl, err
	}
	flowKeysJSON, err := marshalStringSlice(limiter.FlowKeys)
	if err != nil {
		return bl, err
	}
	err = r.db.QueryRow(
		r.ctx, `
		UPDATE bandwidth_limiters
		SET
			username=$1,
			outbound=$2,
			strategy=$3,
			connection_type=$4,
			mode=$5,
			flow_keys=$6,
			speed=$7,
			raw_speed=$8,
			updated_at=$9
		WHERE id=$10
		RETURNING
			id,
			ARRAY(
				SELECT squad_id
				FROM bandwidth_limiter_to_squad
				WHERE bandwidth_limiter_to_squad.bandwidth_limiter_id = bandwidth_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			connection_type,
			mode,
			flow_keys,
			speed,
			raw_speed,
			created_at,
			updated_at
	`,
		limiter.Username,
		limiter.Outbound,
		limiter.Strategy,
		limiter.ConnectionType,
		limiter.Mode,
		flowKeysJSON,
		limiter.Speed,
		raw.Value(),
		time.Now(),
		id,
	).Scan(
		&bl.ID,
		&bl.SquadIDs,
		&bl.Username,
		&bl.Outbound,
		&bl.Strategy,
		&bl.ConnectionType,
		&bl.Mode,
		&flowKeys,
		&bl.Speed,
		&bl.RawSpeed,
		&bl.CreatedAt,
		&bl.UpdatedAt,
	)
	bl.FlowKeys = []string(flowKeys)
	return bl, err
}

func (r *PostgreSQLRepository) DeleteBandwidthLimiter(id int) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	var flowKeys sql.SliceJSON[string]
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return bl, err
	}
	defer tx.Rollback(r.ctx)
	var squadIDs []int
	squadRows, err := tx.Query(r.ctx, `SELECT squad_id FROM bandwidth_limiter_to_squad WHERE bandwidth_limiter_id = $1`, id)
	if err != nil {
		return bl, err
	}
	for squadRows.Next() {
		var squadID int
		if err = squadRows.Scan(&squadID); err != nil {
			squadRows.Close()
			return bl, err
		}
		squadIDs = append(squadIDs, squadID)
	}
	squadRows.Close()
	if err = squadRows.Err(); err != nil {
		return bl, err
	}
	err = tx.QueryRow(r.ctx, `
		DELETE FROM bandwidth_limiters
		WHERE id=$1
		RETURNING
			id,
			username,
			outbound,
			strategy,
			connection_type,
			mode,
			flow_keys,
			speed,
			raw_speed,
			created_at,
			updated_at
	`, id).Scan(
		&bl.ID,
		&bl.Username,
		&bl.Outbound,
		&bl.Strategy,
		&bl.ConnectionType,
		&bl.Mode,
		&flowKeys,
		&bl.Speed,
		&bl.RawSpeed,
		&bl.CreatedAt,
		&bl.UpdatedAt,
	)
	if err != nil {
		return bl, err
	}
	bl.SquadIDs = squadIDs
	bl.FlowKeys = []string(flowKeys)
	return bl, tx.Commit(r.ctx)
}

func (r *PostgreSQLRepository) CreateTrafficLimiter(limiter constant.TrafficLimiterCreate) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return tl, err
	}
	defer tx.Rollback(r.ctx)
	bytesQuota, err := json.Marshal(limiter.Quota)
	if err != nil {
		return tl, err
	}
	rawQuota := &byteformats.NetworkBytesCompat{}
	if err = rawQuota.UnmarshalJSON(bytesQuota); err != nil {
		return tl, err
	}
	now := time.Now()
	err = tx.QueryRow(
		r.ctx, `
		INSERT INTO traffic_limiters
		(
			username,
			outbound,
			strategy,
			mode,
			quota,
			raw_quota,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING
			id,
			username,
			outbound,
			strategy,
			mode,
			raw_used,
			quota,
			raw_quota,
			CASE WHEN raw_quota = 0 THEN 0 ELSE LEAST(100, FLOOR(raw_used * 100.0 / raw_quota)::int) END AS usage,
			created_at,
			updated_at
	`,
		limiter.Username,
		limiter.Outbound,
		limiter.Strategy,
		limiter.Mode,
		limiter.Quota,
		rawQuota.Value(),
		now,
		now,
	).Scan(
		&tl.ID,
		&tl.Username,
		&tl.Outbound,
		&tl.Strategy,
		&tl.Mode,
		&tl.RawUsed,
		&tl.Quota,
		&tl.RawQuota,
		&tl.Usage,
		&tl.CreatedAt,
		&tl.UpdatedAt,
	)
	if err != nil {
		return tl, err
	}
	rows := make([][]any, len(limiter.SquadIDs))
	for i, squadID := range limiter.SquadIDs {
		rows[i] = []any{tl.ID, squadID}
	}
	_, err = tx.CopyFrom(
		r.ctx,
		pgx.Identifier{"traffic_limiter_to_squad"},
		[]string{"traffic_limiter_id", "squad_id"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return tl, err
	}
	tl.SquadIDs = limiter.SquadIDs
	err = tx.Commit(r.ctx)
	if err != nil {
		return tl, err
	}
	return tl, err
}

func (r *PostgreSQLRepository) GetTrafficLimiters(filters map[string][]string) ([]constant.TrafficLimiter, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select(
			"id",
			`ARRAY(
				SELECT squad_id
				FROM traffic_limiter_to_squad
				WHERE traffic_limiter_to_squad.traffic_limiter_id = traffic_limiters.id
			) as squad_ids`,
			"username",
			"outbound",
			"strategy",
			"mode",
			"raw_used",
			"quota",
			"raw_quota",
			"CASE WHEN raw_quota = 0 THEN 0 ELSE LEAST(100, FLOOR(raw_used * 100.0 / raw_quota)::int) END AS usage",
			"created_at",
			"updated_at",
		).
		From("traffic_limiters")

	for k, v := range filters {
		if f, ok := trafficLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return nil, err
			}
		}
	}
	query, args := sb.Build()
	rows, err := r.db.Query(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.TrafficLimiter
	for rows.Next() {
		var tl constant.TrafficLimiter
		if err := rows.Scan(
			&tl.ID,
			&tl.SquadIDs,
			&tl.Username,
			&tl.Outbound,
			&tl.Strategy,
			&tl.Mode,
			&tl.RawUsed,
			&tl.Quota,
			&tl.RawQuota,
			&tl.Usage,
			&tl.CreatedAt,
			&tl.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, tl)
	}
	return result, rows.Err()
}

func (r *PostgreSQLRepository) GetTrafficLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select("COUNT(*)").
		From("traffic_limiters")
	for k, v := range filters {
		if f, ok := trafficLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return 0, err
			}
		}
	}
	query, args := sb.Build()
	var count int
	err := r.db.QueryRow(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) GetTrafficLimiter(id int) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	err := r.db.QueryRow(r.ctx, `
		SELECT
			id,
			ARRAY(
				SELECT squad_id
				FROM traffic_limiter_to_squad
				WHERE traffic_limiter_to_squad.traffic_limiter_id = traffic_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			mode,
			raw_used,
			quota,
			raw_quota,
			CASE WHEN raw_quota = 0 THEN 0 ELSE LEAST(100, FLOOR(raw_used * 100.0 / raw_quota)::int) END AS usage,
			created_at,
			updated_at
		FROM traffic_limiters
		WHERE id=$1
	`, id).Scan(
		&tl.ID,
		&tl.SquadIDs,
		&tl.Username,
		&tl.Outbound,
		&tl.Strategy,
		&tl.Mode,
		&tl.RawUsed,
		&tl.Quota,
		&tl.RawQuota,
		&tl.Usage,
		&tl.CreatedAt,
		&tl.UpdatedAt,
	)
	return tl, notFoundErr(err)
}

func (r *PostgreSQLRepository) UpdateTrafficLimiter(id int, limiter constant.TrafficLimiterUpdate) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	bytesQuota, err := json.Marshal(limiter.Quota)
	if err != nil {
		return tl, err
	}
	rawQuota := &byteformats.NetworkBytesCompat{}
	if err = rawQuota.UnmarshalJSON(bytesQuota); err != nil {
		return tl, err
	}
	err = r.db.QueryRow(
		r.ctx, `
		UPDATE traffic_limiters
		SET
			username=$1,
			outbound=$2,
			strategy=$3,
			mode=$4,
			quota=$5,
			raw_quota=$6,
			updated_at=$7
		WHERE id=$8
		RETURNING
			id,
			ARRAY(
				SELECT squad_id
				FROM traffic_limiter_to_squad
				WHERE traffic_limiter_to_squad.traffic_limiter_id = traffic_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			mode,
			raw_used,
			quota,
			raw_quota,
			CASE WHEN raw_quota = 0 THEN 0 ELSE LEAST(100, FLOOR(raw_used * 100.0 / raw_quota)::int) END AS usage,
			created_at,
			updated_at
	`,
		limiter.Username,
		limiter.Outbound,
		limiter.Strategy,
		limiter.Mode,
		limiter.Quota,
		rawQuota.Value(),
		time.Now(),
		id,
	).Scan(
		&tl.ID,
		&tl.SquadIDs,
		&tl.Username,
		&tl.Outbound,
		&tl.Strategy,
		&tl.Mode,
		&tl.RawUsed,
		&tl.Quota,
		&tl.RawQuota,
		&tl.Usage,
		&tl.CreatedAt,
		&tl.UpdatedAt,
	)
	return tl, err
}

func (r *PostgreSQLRepository) UpdateTrafficLimiterUsed(id int, current uint64) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	err := r.db.QueryRow(
		r.ctx, `
		UPDATE traffic_limiters
		SET
			raw_used=$1,
			updated_at=$2
		WHERE id=$3
		RETURNING
			id,
			ARRAY(
				SELECT squad_id
				FROM traffic_limiter_to_squad
				WHERE traffic_limiter_to_squad.traffic_limiter_id = traffic_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			mode,
			raw_used,
			quota,
			raw_quota,
			CASE WHEN raw_quota = 0 THEN 0 ELSE LEAST(100, FLOOR(raw_used * 100.0 / raw_quota)::int) END AS usage,
			created_at,
			updated_at
	`,
		current,
		time.Now(),
		id,
	).Scan(
		&tl.ID,
		&tl.SquadIDs,
		&tl.Username,
		&tl.Outbound,
		&tl.Strategy,
		&tl.Mode,
		&tl.RawUsed,
		&tl.Quota,
		&tl.RawQuota,
		&tl.Usage,
		&tl.CreatedAt,
		&tl.UpdatedAt,
	)
	return tl, err
}

func (r *PostgreSQLRepository) DeleteTrafficLimiter(id int) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return tl, err
	}
	defer tx.Rollback(r.ctx)
	var squadIDs []int
	squadRows, err := tx.Query(r.ctx, `SELECT squad_id FROM traffic_limiter_to_squad WHERE traffic_limiter_id = $1`, id)
	if err != nil {
		return tl, err
	}
	for squadRows.Next() {
		var squadID int
		if err = squadRows.Scan(&squadID); err != nil {
			squadRows.Close()
			return tl, err
		}
		squadIDs = append(squadIDs, squadID)
	}
	squadRows.Close()
	if err = squadRows.Err(); err != nil {
		return tl, err
	}
	err = tx.QueryRow(r.ctx, `
		DELETE FROM traffic_limiters
		WHERE id=$1
		RETURNING
			id,
			username,
			outbound,
			strategy,
			mode,
			raw_used,
			quota,
			raw_quota,
			CASE WHEN raw_quota = 0 THEN 0 ELSE LEAST(100, FLOOR(raw_used * 100.0 / raw_quota)::int) END AS usage,
			created_at,
			updated_at
	`, id).Scan(
		&tl.ID,
		&tl.Username,
		&tl.Outbound,
		&tl.Strategy,
		&tl.Mode,
		&tl.RawUsed,
		&tl.Quota,
		&tl.RawQuota,
		&tl.Usage,
		&tl.CreatedAt,
		&tl.UpdatedAt,
	)
	if err != nil {
		return tl, err
	}
	tl.SquadIDs = squadIDs
	return tl, tx.Commit(r.ctx)
}

func (r *PostgreSQLRepository) CreateRateLimiter(limiter constant.RateLimiterCreate) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return rl, err
	}
	defer tx.Rollback(r.ctx)
	now := time.Now()
	err = tx.QueryRow(
		r.ctx, `
		INSERT INTO rate_limiters
		(
			username,
			outbound,
			strategy,
			connection_type,
			count,
			interval,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING
			id,
			username,
			outbound,
			strategy,
			connection_type,
			count,
			interval,
			created_at,
			updated_at
	`,
		limiter.Username,
		limiter.Outbound,
		limiter.Strategy,
		limiter.ConnectionType,
		limiter.Count,
		limiter.Interval,
		now,
		now,
	).Scan(
		&rl.ID,
		&rl.Username,
		&rl.Outbound,
		&rl.Strategy,
		&rl.ConnectionType,
		&rl.Count,
		&rl.Interval,
		&rl.CreatedAt,
		&rl.UpdatedAt,
	)
	if err != nil {
		return rl, err
	}
	rows := make([][]any, len(limiter.SquadIDs))
	for i, squadID := range limiter.SquadIDs {
		rows[i] = []any{rl.ID, squadID}
	}
	_, err = tx.CopyFrom(
		r.ctx,
		pgx.Identifier{"rate_limiter_to_squad"},
		[]string{"rate_limiter_id", "squad_id"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return rl, err
	}
	rl.SquadIDs = limiter.SquadIDs
	err = tx.Commit(r.ctx)
	if err != nil {
		return rl, err
	}
	return rl, err
}

func (r *PostgreSQLRepository) GetRateLimiters(filters map[string][]string) ([]constant.RateLimiter, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select(
			"id",
			`ARRAY(
				SELECT squad_id
				FROM rate_limiter_to_squad
				WHERE rate_limiter_to_squad.rate_limiter_id = rate_limiters.id
			) as squad_ids`,
			"username",
			"outbound",
			"strategy",
			"connection_type",
			"count",
			"interval",
			"created_at",
			"updated_at",
		).
		From("rate_limiters")

	for k, v := range filters {
		if f, ok := rateLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return nil, err
			}
		}
	}
	query, args := sb.Build()
	rows, err := r.db.Query(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.RateLimiter
	for rows.Next() {
		var rl constant.RateLimiter
		if err := rows.Scan(
			&rl.ID,
			&rl.SquadIDs,
			&rl.Username,
			&rl.Outbound,
			&rl.Strategy,
			&rl.ConnectionType,
			&rl.Count,
			&rl.Interval,
			&rl.CreatedAt,
			&rl.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, rl)
	}
	return result, rows.Err()
}

func (r *PostgreSQLRepository) GetRateLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder().
		Select("COUNT(*)").
		From("rate_limiters")
	for k, v := range filters {
		if f, ok := rateLimiterFilters[k]; ok {
			if err := f(sb, v); err != nil {
				return 0, err
			}
		}
	}
	query, args := sb.Build()
	var count int
	err := r.db.QueryRow(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *PostgreSQLRepository) GetRateLimiter(id int) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	err := r.db.QueryRow(r.ctx, `
		SELECT
			id,
			ARRAY(
				SELECT squad_id
				FROM rate_limiter_to_squad
				WHERE rate_limiter_to_squad.rate_limiter_id = rate_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			connection_type,
			count,
			interval,
			created_at,
			updated_at
		FROM rate_limiters
		WHERE id=$1
	`, id).Scan(
		&rl.ID,
		&rl.SquadIDs,
		&rl.Username,
		&rl.Outbound,
		&rl.Strategy,
		&rl.ConnectionType,
		&rl.Count,
		&rl.Interval,
		&rl.CreatedAt,
		&rl.UpdatedAt,
	)
	return rl, notFoundErr(err)
}

func (r *PostgreSQLRepository) UpdateRateLimiter(id int, limiter constant.RateLimiterUpdate) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	err := r.db.QueryRow(
		r.ctx, `
		UPDATE rate_limiters
		SET
			username=$1,
			outbound=$2,
			strategy=$3,
			connection_type=$4,
			count=$5,
			interval=$6,
			updated_at=$7
		WHERE id=$8
		RETURNING
			id,
			ARRAY(
				SELECT squad_id
				FROM rate_limiter_to_squad
				WHERE rate_limiter_to_squad.rate_limiter_id = rate_limiters.id
			) as squad_ids,
			username,
			outbound,
			strategy,
			connection_type,
			count,
			interval,
			created_at,
			updated_at
	`,
		limiter.Username,
		limiter.Outbound,
		limiter.Strategy,
		limiter.ConnectionType,
		limiter.Count,
		limiter.Interval,
		time.Now(),
		id,
	).Scan(
		&rl.ID,
		&rl.SquadIDs,
		&rl.Username,
		&rl.Outbound,
		&rl.Strategy,
		&rl.ConnectionType,
		&rl.Count,
		&rl.Interval,
		&rl.CreatedAt,
		&rl.UpdatedAt,
	)
	return rl, err
}

func (r *PostgreSQLRepository) DeleteRateLimiter(id int) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return rl, err
	}
	defer tx.Rollback(r.ctx)
	var squadIDs []int
	squadRows, err := tx.Query(r.ctx, `SELECT squad_id FROM rate_limiter_to_squad WHERE rate_limiter_id = $1`, id)
	if err != nil {
		return rl, err
	}
	for squadRows.Next() {
		var squadID int
		if err = squadRows.Scan(&squadID); err != nil {
			squadRows.Close()
			return rl, err
		}
		squadIDs = append(squadIDs, squadID)
	}
	squadRows.Close()
	if err = squadRows.Err(); err != nil {
		return rl, err
	}
	err = tx.QueryRow(r.ctx, `
		DELETE FROM rate_limiters
		WHERE id=$1
		RETURNING
			id,
			username,
			outbound,
			strategy,
			connection_type,
			count,
			interval,
			created_at,
			updated_at
	`, id).Scan(
		&rl.ID,
		&rl.Username,
		&rl.Outbound,
		&rl.Strategy,
		&rl.ConnectionType,
		&rl.Count,
		&rl.Interval,
		&rl.CreatedAt,
		&rl.UpdatedAt,
	)
	if err != nil {
		return rl, err
	}
	rl.SquadIDs = squadIDs
	return rl, tx.Commit(r.ctx)
}

func init() {
	squadFilters = map[string]sql.Filter{"id": sql.EqualFilter("id"),
		"id_in":            sql.InFilter("id"),
		"pk":               sql.EqualFilter("id"),
		"name":             sql.EqualFilter("name"),
		"created_at_start": sql.GreaterThanFilter("created_at"),
		"created_at_end":   sql.LessThanFilter("created_at"),
		"updated_at_start": sql.GreaterThanFilter("updated_at"),
		"updated_at_end":   sql.LessThanFilter("updated_at"),
		"sort_asc":         sql.SortAscFilter([]string{"id", "name", "created_at", "updated_at"}),
		"sort_desc":        sql.SortDescFilter([]string{"id", "name", "created_at", "updated_at"}),
		"offset":           sql.OffsetFilter(),
		"limit":            sql.LimitFilter()}
	nodeFilters = map[string]sql.Filter{"uuid": sql.EqualFilter("uuid"),
		"pk":   sql.EqualFilter("uuid"),
		"name": sql.EqualFilter("name"),
		"squad_id_in": sql.ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.PostgreSQL.NewSelectBuilder().
				Select(
					"squad_id",
				).
				Where(
					"node_to_squad.node_uuid = nodes.uuid",
				).
				From(
					"node_to_squad",
				)
		}, "node_to_squad.squad_id"),
		"created_at_start": sql.GreaterThanFilter("created_at"),
		"created_at_end":   sql.LessThanFilter("created_at"),
		"updated_at_start": sql.GreaterThanFilter("updated_at"),
		"updated_at_end":   sql.LessThanFilter("updated_at"),
		"sort_asc":         sql.SortAscFilter([]string{"uuid", "name", "created_at", "updated_at"}),
		"sort_desc":        sql.SortDescFilter([]string{"uuid", "name", "created_at", "updated_at"}),
		"offset":           sql.OffsetFilter(),
		"limit":            sql.LimitFilter()}
	userFilters = map[string]sql.Filter{"id": sql.EqualFilter("id"),
		"pk": sql.EqualFilter("id"),
		"squad_id_in": sql.ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.PostgreSQL.NewSelectBuilder().
				Select(
					"squad_id",
				).
				Where(
					"user_to_squad.user_id = users.id",
				).
				From(
					"user_to_squad",
				)
		}, "user_to_squad.squad_id"),
		"username":         sql.EqualFilter("username"),
		"inbound":          sql.EqualFilter("inbound"),
		"created_at_start": sql.GreaterThanFilter("created_at"),
		"created_at_end":   sql.LessThanFilter("created_at"),
		"updated_at_start": sql.GreaterThanFilter("updated_at"),
		"updated_at_end":   sql.LessThanFilter("updated_at"),
		"sort_asc":         sql.SortAscFilter([]string{"id", "username", "inbound", "type", "created_at", "updated_at"}),
		"sort_desc":        sql.SortDescFilter([]string{"id", "username", "inbound", "type", "created_at", "updated_at"}),
		"offset":           sql.OffsetFilter(),
		"limit":            sql.LimitFilter()}
	connectionLimiterFilters = map[string]sql.Filter{"id": sql.EqualFilter("id"),
		"pk": sql.EqualFilter("id"),
		"squad_id_in": sql.ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.PostgreSQL.NewSelectBuilder().
				Select(
					"squad_id",
				).
				Where(
					"connection_limiter_to_squad.connection_limiter_id = connection_limiters.id",
				).
				From(
					"connection_limiter_to_squad",
				)
		}, "connection_limiter_to_squad.squad_id"),
		"strategy":         sql.EqualFilter("strategy"),
		"username":         sql.EqualFilter("username"),
		"outbound":         sql.EqualFilter("outbound"),
		"connection_type":  sql.EqualFilter("connection_type"),
		"lock_type":        sql.EqualFilter("lock_type"),
		"created_at_start": sql.GreaterThanFilter("created_at"),
		"created_at_end":   sql.LessThanFilter("created_at"),
		"updated_at_start": sql.GreaterThanFilter("updated_at"),
		"updated_at_end":   sql.LessThanFilter("updated_at"),
		"sort_asc":         sql.SortAscFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "lock_type", "count", "created_at", "updated_at"}),
		"sort_desc":        sql.SortDescFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "lock_type", "count", "created_at", "updated_at"}),
		"offset":           sql.OffsetFilter(),
		"limit":            sql.LimitFilter()}
	bandwidthLimiterFilters = map[string]sql.Filter{"id": sql.EqualFilter("id"),
		"pk": sql.EqualFilter("id"),
		"squad_id_in": sql.ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.PostgreSQL.NewSelectBuilder().
				Select(
					"squad_id",
				).
				Where(
					"bandwidth_limiter_to_squad.bandwidth_limiter_id = bandwidth_limiters.id",
				).
				From(
					"bandwidth_limiter_to_squad",
				)
		}, "bandwidth_limiter_to_squad.squad_id"),
		"strategy":         sql.EqualFilter("strategy"),
		"mode":             sql.EqualFilter("mode"),
		"username":         sql.EqualFilter("username"),
		"created_at_start": sql.GreaterThanFilter("created_at"),
		"created_at_end":   sql.LessThanFilter("created_at"),
		"updated_at_start": sql.GreaterThanFilter("updated_at"),
		"updated_at_end":   sql.LessThanFilter("updated_at"),
		"sort_asc": sql.ReplacedSortAscFilter(map[string]string{"speed": "raw_speed"},
			[]string{"id", "username", "outbound", "strategy", "connection_type", "mode", "raw_speed", "created_at", "updated_at"}),
		"sort_desc": sql.ReplacedSortDescFilter(map[string]string{"speed": "raw_speed"},
			[]string{"id", "username", "outbound", "strategy", "connection_type", "mode", "raw_speed", "created_at", "updated_at"}),
		"offset": sql.OffsetFilter(),
		"limit":  sql.LimitFilter()}
	trafficLimiterFilters = map[string]sql.Filter{"id": sql.EqualFilter("id"),
		"pk": sql.EqualFilter("id"),
		"squad_id_in": sql.ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.PostgreSQL.NewSelectBuilder().
				Select(
					"squad_id",
				).
				Where(
					"traffic_limiter_to_squad.traffic_limiter_id = traffic_limiters.id",
				).
				From(
					"traffic_limiter_to_squad",
				)
		}, "traffic_limiter_to_squad.squad_id"),
		"username":         sql.EqualFilter("username"),
		"outbound":         sql.EqualFilter("outbound"),
		"strategy":         sql.EqualFilter("strategy"),
		"mode":             sql.EqualFilter("mode"),
		"used_start":       sql.SpeedGreaterEqualThanFilter("raw_used"),
		"used_end":         sql.SpeedLessEqualThanFilter("raw_used"),
		"quota_start":      sql.SpeedGreaterEqualThanFilter("raw_quota"),
		"quota_end":        sql.SpeedLessEqualThanFilter("raw_quota"),
		"created_at_start": sql.GreaterThanFilter("created_at"),
		"created_at_end":   sql.LessThanFilter("created_at"),
		"updated_at_start": sql.GreaterThanFilter("updated_at"),
		"updated_at_end":   sql.LessThanFilter("updated_at"),
		"sort_asc": sql.ReplacedSortAscFilter(map[string]string{"used": "raw_used", "quota": "raw_quota"},
			[]string{"id", "username", "outbound", "strategy", "mode", "raw_used", "raw_quota", "created_at", "updated_at"}),
		"sort_desc": sql.ReplacedSortDescFilter(map[string]string{"used": "raw_used", "quota": "raw_quota"},
			[]string{"id", "username", "outbound", "strategy", "mode", "raw_used", "raw_quota", "created_at", "updated_at"}),
		"offset": sql.OffsetFilter(),
		"limit":  sql.LimitFilter()}
	rateLimiterFilters = map[string]sql.Filter{"id": sql.EqualFilter("id"),
		"pk": sql.EqualFilter("id"),
		"squad_id_in": sql.ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.PostgreSQL.NewSelectBuilder().
				Select(
					"squad_id",
				).
				Where(
					"rate_limiter_to_squad.rate_limiter_id = rate_limiters.id",
				).
				From(
					"rate_limiter_to_squad",
				)
		}, "rate_limiter_to_squad.squad_id"),
		"strategy":         sql.EqualFilter("strategy"),
		"username":         sql.EqualFilter("username"),
		"outbound":         sql.EqualFilter("outbound"),
		"connection_type":  sql.EqualFilter("connection_type"),
		"interval":         sql.EqualFilter("interval"),
		"count_start":      sql.GreaterEqualThanFilter("count"),
		"count_end":        sql.LessEqualThanFilter("count"),
		"created_at_start": sql.GreaterThanFilter("created_at"),
		"created_at_end":   sql.LessThanFilter("created_at"),
		"updated_at_start": sql.GreaterThanFilter("updated_at"),
		"updated_at_end":   sql.LessThanFilter("updated_at"),
		"sort_asc":         sql.SortAscFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "count", "interval", "created_at", "updated_at"}),
		"sort_desc":        sql.SortDescFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "count", "interval", "created_at", "updated_at"}),
		"offset":           sql.OffsetFilter(),
		"limit":            sql.LimitFilter()}
}
