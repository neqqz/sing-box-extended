package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/huandu/go-sqlbuilder"
	"github.com/sagernet/sing-box/service/manager/constant"
	"github.com/sagernet/sing/common/byteformats"
	_ "modernc.org/sqlite"
)

var squadFilters, nodeFilters, userFilters, bandwidthLimiterFilters, connectionLimiterFilters, trafficLimiterFilters, rateLimiterFilters map[string]Filter

type SQLiteRepository struct {
	db  *sql.DB
	ctx context.Context
}

func NewSQLiteRepository(ctx context.Context, dsn string) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := Migrate(db); err != nil && err != migrate.ErrNoChange {
		db.Close()
		return nil, err
	}
	return &SQLiteRepository{db: db, ctx: ctx}, nil
}

func notFoundErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return constant.ErrNotFound
	}
	return err
}

func (r *SQLiteRepository) CreateSquad(squad constant.SquadCreate) (constant.Squad, error) {
	var s constant.Squad
	now := time.Now()
	err := r.db.QueryRowContext(
		r.ctx, `
		INSERT INTO squads
		(
			name,
			created_at,
			updated_at
		)
		VALUES (?, ?, ?)
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

func (r *SQLiteRepository) GetSquads(filters map[string][]string) ([]constant.Squad, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	rows, err := r.db.QueryContext(r.ctx, query, args...)
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

func (r *SQLiteRepository) GetSquadsCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	err := r.db.QueryRowContext(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) GetSquad(id int) (constant.Squad, error) {
	var s constant.Squad
	err := r.db.QueryRowContext(r.ctx, `
		SELECT
			id,
			name,
			created_at,
			updated_at
		FROM squads
		WHERE id=?
	`, id).Scan(
		&s.ID,
		&s.Name,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	return s, notFoundErr(err)
}

func (r *SQLiteRepository) UpdateSquad(id int, squad constant.SquadUpdate) (constant.Squad, error) {
	var s constant.Squad
	err := r.db.QueryRowContext(
		r.ctx, `
		UPDATE squads
		SET
			name=?,
			updated_at=?
		WHERE id=?
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

func (r *SQLiteRepository) DeleteSquad(id int) (constant.DeletedSquad, error) {
	var result constant.DeletedSquad
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	affectedNodeRows, err := tx.QueryContext(r.ctx, `DELETE FROM node_to_squad WHERE squad_id=? RETURNING node_uuid`, id)
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
		if _, err = tx.ExecContext(r.ctx, `DELETE FROM `+table+` WHERE squad_id=?`, id); err != nil {
			return result, err
		}
	}
	err = tx.QueryRowContext(r.ctx, `
		DELETE FROM squads
		WHERE id=?
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
	orphanedNodeRows, err := tx.QueryContext(r.ctx, `
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
	if _, err = tx.ExecContext(r.ctx, `
		DELETE FROM users
		WHERE NOT EXISTS (SELECT 1 FROM user_to_squad WHERE user_to_squad.user_id = users.id)
	`); err != nil {
		return result, err
	}
	connRows, err := tx.QueryContext(r.ctx, `
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
	if _, err = tx.ExecContext(r.ctx, `
		DELETE FROM bandwidth_limiters
		WHERE NOT EXISTS (SELECT 1 FROM bandwidth_limiter_to_squad WHERE bandwidth_limiter_to_squad.bandwidth_limiter_id = bandwidth_limiters.id)
	`); err != nil {
		return result, err
	}
	trafficRows, err := tx.QueryContext(r.ctx, `
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
	if _, err = tx.ExecContext(r.ctx, `
		DELETE FROM rate_limiters
		WHERE NOT EXISTS (SELECT 1 FROM rate_limiter_to_squad WHERE rate_limiter_to_squad.rate_limiter_id = rate_limiters.id)
	`); err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (r *SQLiteRepository) CreateNode(node constant.NodeCreate) (constant.Node, error) {
	var n constant.Node
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return n, err
	}
	defer tx.Rollback()
	now := time.Now()
	err = tx.QueryRowContext(
		r.ctx, `
		INSERT INTO nodes (
			uuid,
			name,
			created_at,
			updated_at
		)
		VALUES (?, ?, ?, ?)
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
	stmt, err := tx.PrepareContext(r.ctx, `INSERT INTO node_to_squad (node_uuid, squad_id) VALUES (?, ?)`)
	if err != nil {
		return n, err
	}
	defer stmt.Close()
	for _, squadID := range node.SquadIDs {
		if _, err = stmt.ExecContext(r.ctx, node.UUID, squadID); err != nil {
			return n, err
		}
	}
	if err = tx.Commit(); err != nil {
		return n, err
	}
	n.SquadIDs = node.SquadIDs
	return n, nil
}

func (r *SQLiteRepository) GetNodes(filters map[string][]string) ([]constant.Node, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
		Select(
			"uuid",
			"name",
			`(
				SELECT json_group_array(squad_id)
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
	rows, err := r.db.QueryContext(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.Node
	for rows.Next() {
		var n constant.Node
		var squadIDs intSliceJSON
		if err := rows.Scan(
			&n.UUID,
			&n.Name,
			&squadIDs,
			&n.CreatedAt,
			&n.UpdatedAt,
		); err != nil {
			return nil, err
		}
		n.SquadIDs = []int(squadIDs)
		result = append(result, n)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) GetNodesCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	err := r.db.QueryRowContext(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) GetNode(uuid string) (constant.Node, error) {
	var n constant.Node
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		SELECT 
			uuid,
			name, 
			(
				SELECT json_group_array(squad_id)
				FROM node_to_squad
				WHERE node_to_squad.node_uuid = nodes.uuid
			) as squad_ids,
			created_at,
			updated_at
		FROM nodes
		WHERE uuid = ?
	`, uuid).Scan(
		&n.UUID,
		&n.Name,
		&squadIDs,
		&n.CreatedAt,
		&n.UpdatedAt,
	)
	n.SquadIDs = []int(squadIDs)
	return n, notFoundErr(err)
}
func (r *SQLiteRepository) UpdateNode(uuid string, node constant.NodeUpdate) (constant.Node, error) {
	var n constant.Node
	err := r.db.QueryRowContext(
		r.ctx, `
		UPDATE nodes
		SET 
			name = ?,
			updated_at = ?
		WHERE uuid = ?
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

func (r *SQLiteRepository) DeleteNode(uuid string) (constant.Node, error) {
	var n constant.Node
	err := r.db.QueryRowContext(r.ctx, `
		DELETE FROM nodes
		WHERE uuid = ?
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

func (r *SQLiteRepository) CreateUser(user constant.UserCreate) (constant.User, error) {
	var u constant.User
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return u, err
	}
	defer tx.Rollback()
	now := time.Now()
	authorizedKeysJSON, err := marshalStringSlice(user.AuthorizedKeys)
	if err != nil {
		return u, err
	}
	var authorizedKeys stringSliceJSON
	err = tx.QueryRowContext(
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
	stmt, err := tx.PrepareContext(r.ctx, `INSERT INTO user_to_squad (user_id, squad_id) VALUES (?, ?)`)
	if err != nil {
		return u, err
	}
	defer stmt.Close()
	for _, squadID := range user.SquadIDs {
		if _, err = stmt.ExecContext(r.ctx, u.ID, squadID); err != nil {
			return u, err
		}
	}
	if err = tx.Commit(); err != nil {
		return u, err
	}
	u.SquadIDs = user.SquadIDs
	return u, nil
}

func (r *SQLiteRepository) GetUsers(filters map[string][]string) ([]constant.User, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
		Select(
			"id",
			`(
				SELECT json_group_array(squad_id)
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
	rows, err := r.db.QueryContext(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.User
	for rows.Next() {
		var u constant.User
		var squadIDs intSliceJSON
		var authorizedKeys stringSliceJSON
		if err := rows.Scan(
			&u.ID,
			&squadIDs,
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
		); err != nil {
			return nil, err
		}
		u.SquadIDs = []int(squadIDs)
		u.AuthorizedKeys = []string(authorizedKeys)
		result = append(result, u)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) GetUsersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	err := r.db.QueryRowContext(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) GetUser(id int) (constant.User, error) {
	var u constant.User
	var squadIDs intSliceJSON
	var authorizedKeys stringSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		SELECT
			id,
			(
				SELECT json_group_array(squad_id)
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
		WHERE id = ?
	`, id).Scan(
		&u.ID,
		&squadIDs,
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
	u.SquadIDs = []int(squadIDs)
	u.AuthorizedKeys = []string(authorizedKeys)
	return u, notFoundErr(err)
}

func (r *SQLiteRepository) UpdateUser(id int, user constant.UserUpdate) (constant.User, error) {
	var u constant.User
	var squadIDs intSliceJSON
	var authorizedKeys stringSliceJSON
	authorizedKeysJSON, err := marshalStringSlice(user.AuthorizedKeys)
	if err != nil {
		return u, err
	}
	err = r.db.QueryRowContext(
		r.ctx, `
		UPDATE users
		SET
			uuid = ?,
			password = ?,
			secret = ?,
			authorized_keys = ?,
			flow = ?,
			alter_id = ?,
			updated_at = ?
		WHERE id = ?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
		&squadIDs,
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
	u.SquadIDs = []int(squadIDs)
	u.AuthorizedKeys = []string(authorizedKeys)
	return u, err
}

func (r *SQLiteRepository) DeleteUser(id int) (constant.User, error) {
	var u constant.User
	var squadIDs intSliceJSON
	var authorizedKeys stringSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		DELETE FROM users
		WHERE id = ?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
	`, id).Scan(
		&u.ID,
		&squadIDs,
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
	u.SquadIDs = []int(squadIDs)
	u.AuthorizedKeys = []string(authorizedKeys)
	return u, err
}

func (r *SQLiteRepository) CreateConnectionLimiter(limiter constant.ConnectionLimiterCreate) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return cl, err
	}
	defer tx.Rollback()
	now := time.Now()
	err = tx.QueryRowContext(
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
	stmt, err := tx.PrepareContext(r.ctx, `INSERT INTO connection_limiter_to_squad (connection_limiter_id, squad_id) VALUES (?, ?)`)
	if err != nil {
		return cl, err
	}
	defer stmt.Close()
	for _, squadID := range limiter.SquadIDs {
		if _, err = stmt.ExecContext(r.ctx, cl.ID, squadID); err != nil {
			return cl, err
		}
	}
	if err = tx.Commit(); err != nil {
		return cl, err
	}
	cl.SquadIDs = limiter.SquadIDs
	return cl, nil
}

func (r *SQLiteRepository) GetConnectionLimiters(filters map[string][]string) ([]constant.ConnectionLimiter, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
		Select(
			"id",
			`(
				SELECT json_group_array(squad_id)
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
	rows, err := r.db.QueryContext(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.ConnectionLimiter
	for rows.Next() {
		var cl constant.ConnectionLimiter
		var squadIDs intSliceJSON
		if err := rows.Scan(
			&cl.ID,
			&squadIDs,
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
		cl.SquadIDs = []int(squadIDs)
		result = append(result, cl)
	}

	return result, rows.Err()
}

func (r *SQLiteRepository) GetConnectionLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	err := r.db.QueryRowContext(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) GetConnectionLimiter(id int) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		SELECT
			id,
			(
				SELECT json_group_array(squad_id)
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
		WHERE id=?
	`, id).Scan(
		&cl.ID,
		&squadIDs,
		&cl.Username,
		&cl.Outbound,
		&cl.Strategy,
		&cl.ConnectionType,
		&cl.LockType,
		&cl.Count,
		&cl.CreatedAt,
		&cl.UpdatedAt,
	)
	cl.SquadIDs = []int(squadIDs)
	return cl, notFoundErr(err)
}

func (r *SQLiteRepository) UpdateConnectionLimiter(id int, limiter constant.ConnectionLimiterUpdate) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(
		r.ctx, `
		UPDATE connection_limiters
		SET
			strategy=?,
			connection_type=?,
			lock_type=?,
			count=?,
			updated_at=?
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
		&squadIDs,
		&cl.Username,
		&cl.Outbound,
		&cl.Strategy,
		&cl.ConnectionType,
		&cl.LockType,
		&cl.Count,
		&cl.CreatedAt,
		&cl.UpdatedAt,
	)
	cl.SquadIDs = []int(squadIDs)
	return cl, err
}

func (r *SQLiteRepository) DeleteConnectionLimiter(id int) (constant.ConnectionLimiter, error) {
	var cl constant.ConnectionLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		DELETE FROM connection_limiters
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
	`, id).Scan(
		&cl.ID,
		&squadIDs,
		&cl.Username,
		&cl.Outbound,
		&cl.Strategy,
		&cl.ConnectionType,
		&cl.LockType,
		&cl.Count,
		&cl.CreatedAt,
		&cl.UpdatedAt,
	)
	cl.SquadIDs = []int(squadIDs)
	return cl, err
}

func (r *SQLiteRepository) CreateBandwidthLimiter(limiter constant.BandwidthLimiterCreate) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return bl, err
	}
	defer tx.Rollback()
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
	var flowKeys stringSliceJSON
	now := time.Now()
	err = tx.QueryRowContext(
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
	stmt, err := tx.PrepareContext(r.ctx, `INSERT INTO bandwidth_limiter_to_squad (bandwidth_limiter_id, squad_id) VALUES (?, ?)`)
	if err != nil {
		return bl, err
	}
	defer stmt.Close()
	for _, squadID := range limiter.SquadIDs {
		if _, err = stmt.ExecContext(r.ctx, bl.ID, squadID); err != nil {
			return bl, err
		}
	}
	if err = tx.Commit(); err != nil {
		return bl, err
	}
	bl.SquadIDs = limiter.SquadIDs
	return bl, nil
}

func (r *SQLiteRepository) GetBandwidthLimiters(filters map[string][]string) ([]constant.BandwidthLimiter, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
		Select(
			"id",
			`(
				SELECT json_group_array(squad_id)
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
	rows, err := r.db.QueryContext(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.BandwidthLimiter
	for rows.Next() {
		var bl constant.BandwidthLimiter
		var squadIDs intSliceJSON
		var flowKeys stringSliceJSON
		if err := rows.Scan(
			&bl.ID,
			&squadIDs,
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
		bl.SquadIDs = []int(squadIDs)
		bl.FlowKeys = []string(flowKeys)
		result = append(result, bl)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) GetBandwidthLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	err := r.db.QueryRowContext(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) GetBandwidthLimiter(id int) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	var squadIDs intSliceJSON
	var flowKeys stringSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		SELECT
			id,
			(
				SELECT json_group_array(squad_id)
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
		WHERE id=?
	`, id).Scan(
		&bl.ID,
		&squadIDs,
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
	bl.SquadIDs = []int(squadIDs)
	bl.FlowKeys = []string(flowKeys)
	return bl, notFoundErr(err)
}

func (r *SQLiteRepository) UpdateBandwidthLimiter(id int, limiter constant.BandwidthLimiterUpdate) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	var squadIDs intSliceJSON
	var flowKeys stringSliceJSON
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
	err = r.db.QueryRowContext(
		r.ctx, `
		UPDATE bandwidth_limiters
		SET
			username=?,
			outbound=?,
			strategy=?,
			connection_type=?,
			mode=?,
			flow_keys=?,
			speed=?,
			raw_speed=?,
			updated_at=?
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
		&squadIDs,
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
	bl.SquadIDs = []int(squadIDs)
	bl.FlowKeys = []string(flowKeys)
	return bl, err
}

func (r *SQLiteRepository) DeleteBandwidthLimiter(id int) (constant.BandwidthLimiter, error) {
	var bl constant.BandwidthLimiter
	var squadIDs intSliceJSON
	var flowKeys stringSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		DELETE FROM bandwidth_limiters
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
	`, id).Scan(
		&bl.ID,
		&squadIDs,
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
	bl.SquadIDs = []int(squadIDs)
	bl.FlowKeys = []string(flowKeys)
	return bl, err
}

func (r *SQLiteRepository) CreateTrafficLimiter(limiter constant.TrafficLimiterCreate) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return tl, err
	}
	defer tx.Rollback()
	bytesQuota, err := json.Marshal(limiter.Quota)
	if err != nil {
		return tl, err
	}
	rawQuota := &byteformats.NetworkBytesCompat{}
	if err = rawQuota.UnmarshalJSON(bytesQuota); err != nil {
		return tl, err
	}
	now := time.Now()
	err = tx.QueryRowContext(
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING
			id,
			username,
			outbound,
			strategy,
			mode,
			raw_used,
			quota,
			raw_quota,
			CASE WHEN raw_quota = 0 THEN 0 ELSE min(100, CAST(raw_used * 100.0 / raw_quota AS INTEGER)) END AS usage,
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
	stmt, err := tx.PrepareContext(r.ctx, `INSERT INTO traffic_limiter_to_squad (traffic_limiter_id, squad_id) VALUES (?, ?)`)
	if err != nil {
		return tl, err
	}
	defer stmt.Close()
	for _, squadID := range limiter.SquadIDs {
		if _, err = stmt.ExecContext(r.ctx, tl.ID, squadID); err != nil {
			return tl, err
		}
	}
	if err = tx.Commit(); err != nil {
		return tl, err
	}
	tl.SquadIDs = limiter.SquadIDs
	return tl, nil
}

func (r *SQLiteRepository) GetTrafficLimiters(filters map[string][]string) ([]constant.TrafficLimiter, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
		Select(
			"id",
			`(
				SELECT json_group_array(squad_id)
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
			"CASE WHEN raw_quota = 0 THEN 0 ELSE min(100, CAST(raw_used * 100.0 / raw_quota AS INTEGER)) END AS usage",
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
	rows, err := r.db.QueryContext(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.TrafficLimiter
	for rows.Next() {
		var tl constant.TrafficLimiter
		var squadIDs intSliceJSON
		if err := rows.Scan(
			&tl.ID,
			&squadIDs,
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
		tl.SquadIDs = []int(squadIDs)
		result = append(result, tl)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) GetTrafficLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	err := r.db.QueryRowContext(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) GetTrafficLimiter(id int) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		SELECT
			id,
			(
				SELECT json_group_array(squad_id)
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
			CASE WHEN raw_quota = 0 THEN 0 ELSE min(100, CAST(raw_used * 100.0 / raw_quota AS INTEGER)) END AS usage,
			created_at,
			updated_at
		FROM traffic_limiters
		WHERE id=?
	`, id).Scan(
		&tl.ID,
		&squadIDs,
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
	tl.SquadIDs = []int(squadIDs)
	return tl, notFoundErr(err)
}

func (r *SQLiteRepository) UpdateTrafficLimiter(id int, limiter constant.TrafficLimiterUpdate) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	var squadIDs intSliceJSON
	bytesQuota, err := json.Marshal(limiter.Quota)
	if err != nil {
		return tl, err
	}
	rawQuota := &byteformats.NetworkBytesCompat{}
	if err = rawQuota.UnmarshalJSON(bytesQuota); err != nil {
		return tl, err
	}
	err = r.db.QueryRowContext(
		r.ctx, `
		UPDATE traffic_limiters
		SET
			username=?,
			outbound=?,
			strategy=?,
			mode=?,
			quota=?,
			raw_quota=?,
			updated_at=?
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
			CASE WHEN raw_quota = 0 THEN 0 ELSE min(100, CAST(raw_used * 100.0 / raw_quota AS INTEGER)) END AS usage,
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
		&squadIDs,
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
	tl.SquadIDs = []int(squadIDs)
	return tl, err
}

func (r *SQLiteRepository) UpdateTrafficLimiterUsed(id int, current uint64) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(
		r.ctx, `
		UPDATE traffic_limiters
		SET
			raw_used=?,
			updated_at=?
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
			CASE WHEN raw_quota = 0 THEN 0 ELSE min(100, CAST(raw_used * 100.0 / raw_quota AS INTEGER)) END AS usage,
			created_at,
			updated_at
	`,
		current,
		time.Now(),
		id,
	).Scan(
		&tl.ID,
		&squadIDs,
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
	tl.SquadIDs = []int(squadIDs)
	return tl, err
}

func (r *SQLiteRepository) DeleteTrafficLimiter(id int) (constant.TrafficLimiter, error) {
	var tl constant.TrafficLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		DELETE FROM traffic_limiters
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
			CASE WHEN raw_quota = 0 THEN 0 ELSE min(100, CAST(raw_used * 100.0 / raw_quota AS INTEGER)) END AS usage,
			created_at,
			updated_at
	`, id).Scan(
		&tl.ID,
		&squadIDs,
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
	tl.SquadIDs = []int(squadIDs)
	return tl, err
}

func (r *SQLiteRepository) CreateRateLimiter(limiter constant.RateLimiterCreate) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return rl, err
	}
	defer tx.Rollback()
	now := time.Now()
	err = tx.QueryRowContext(
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
	stmt, err := tx.PrepareContext(r.ctx, `INSERT INTO rate_limiter_to_squad (rate_limiter_id, squad_id) VALUES (?, ?)`)
	if err != nil {
		return rl, err
	}
	defer stmt.Close()
	for _, squadID := range limiter.SquadIDs {
		if _, err = stmt.ExecContext(r.ctx, rl.ID, squadID); err != nil {
			return rl, err
		}
	}
	if err = tx.Commit(); err != nil {
		return rl, err
	}
	rl.SquadIDs = limiter.SquadIDs
	return rl, nil
}

func (r *SQLiteRepository) GetRateLimiters(filters map[string][]string) ([]constant.RateLimiter, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
		Select(
			"id",
			`(
				SELECT json_group_array(squad_id)
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
	rows, err := r.db.QueryContext(r.ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []constant.RateLimiter
	for rows.Next() {
		var rl constant.RateLimiter
		var squadIDs intSliceJSON
		if err := rows.Scan(
			&rl.ID,
			&squadIDs,
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
		rl.SquadIDs = []int(squadIDs)
		result = append(result, rl)
	}
	return result, rows.Err()
}

func (r *SQLiteRepository) GetRateLimitersCount(filters map[string][]string) (int, error) {
	sb := sqlbuilder.SQLite.NewSelectBuilder().
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
	err := r.db.QueryRowContext(r.ctx, query, args...).Scan(&count)
	return count, err
}

func (r *SQLiteRepository) GetRateLimiter(id int) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		SELECT
			id,
			(
				SELECT json_group_array(squad_id)
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
		WHERE id=?
	`, id).Scan(
		&rl.ID,
		&squadIDs,
		&rl.Username,
		&rl.Outbound,
		&rl.Strategy,
		&rl.ConnectionType,
		&rl.Count,
		&rl.Interval,
		&rl.CreatedAt,
		&rl.UpdatedAt,
	)
	rl.SquadIDs = []int(squadIDs)
	return rl, notFoundErr(err)
}

func (r *SQLiteRepository) UpdateRateLimiter(id int, limiter constant.RateLimiterUpdate) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(
		r.ctx, `
		UPDATE rate_limiters
		SET
			username=?,
			outbound=?,
			strategy=?,
			connection_type=?,
			count=?,
			interval=?,
			updated_at=?
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
		&squadIDs,
		&rl.Username,
		&rl.Outbound,
		&rl.Strategy,
		&rl.ConnectionType,
		&rl.Count,
		&rl.Interval,
		&rl.CreatedAt,
		&rl.UpdatedAt,
	)
	rl.SquadIDs = []int(squadIDs)
	return rl, err
}

func (r *SQLiteRepository) DeleteRateLimiter(id int) (constant.RateLimiter, error) {
	var rl constant.RateLimiter
	var squadIDs intSliceJSON
	err := r.db.QueryRowContext(r.ctx, `
		DELETE FROM rate_limiters
		WHERE id=?
		RETURNING
			id,
			(
				SELECT json_group_array(squad_id)
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
	`, id).Scan(
		&rl.ID,
		&squadIDs,
		&rl.Username,
		&rl.Outbound,
		&rl.Strategy,
		&rl.ConnectionType,
		&rl.Count,
		&rl.Interval,
		&rl.CreatedAt,
		&rl.UpdatedAt,
	)
	rl.SquadIDs = []int(squadIDs)
	return rl, err
}

func init() {
	squadFilters = map[string]Filter{
		"id":               EqualFilter("id"),
		"id_in":            InFilter("id"),
		"pk":               EqualFilter("id"),
		"name":             EqualFilter("name"),
		"created_at_start": GreaterThanFilter("created_at"),
		"created_at_end":   LessThanFilter("created_at"),
		"updated_at_start": GreaterThanFilter("updated_at"),
		"updated_at_end":   LessThanFilter("updated_at"),
		"sort_asc":         SortAscFilter([]string{"id", "name", "created_at", "updated_at"}),
		"sort_desc":        SortDescFilter([]string{"id", "name", "created_at", "updated_at"}),
		"offset":           OffsetFilter(),
		"limit":            LimitFilter(),
	}
	nodeFilters = map[string]Filter{
		"uuid": EqualFilter("uuid"),
		"pk":   EqualFilter("uuid"),
		"name": EqualFilter("name"),
		"squad_id_in": ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.SQLite.NewSelectBuilder().
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
		"created_at_start": GreaterThanFilter("created_at"),
		"created_at_end":   LessThanFilter("created_at"),
		"updated_at_start": GreaterThanFilter("updated_at"),
		"updated_at_end":   LessThanFilter("updated_at"),
		"sort_asc":         SortAscFilter([]string{"uuid", "name", "created_at", "updated_at"}),
		"sort_desc":        SortDescFilter([]string{"uuid", "name", "created_at", "updated_at"}),
		"offset":           OffsetFilter(),
		"limit":            LimitFilter(),
	}
	userFilters = map[string]Filter{
		"id": EqualFilter("id"),
		"pk": EqualFilter("id"),
		"squad_id_in": ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.SQLite.NewSelectBuilder().
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
		"username":         EqualFilter("username"),
		"inbound":          EqualFilter("inbound"),
		"created_at_start": GreaterThanFilter("created_at"),
		"created_at_end":   LessThanFilter("created_at"),
		"updated_at_start": GreaterThanFilter("updated_at"),
		"updated_at_end":   LessThanFilter("updated_at"),
		"sort_asc":         SortAscFilter([]string{"id", "username", "inbound", "type", "created_at", "updated_at"}),
		"sort_desc":        SortDescFilter([]string{"id", "username", "inbound", "type", "created_at", "updated_at"}),
		"offset":           OffsetFilter(),
		"limit":            LimitFilter(),
	}
	connectionLimiterFilters = map[string]Filter{
		"id": EqualFilter("id"),
		"pk": EqualFilter("id"),
		"squad_id_in": ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.SQLite.NewSelectBuilder().
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
		"strategy":         EqualFilter("strategy"),
		"username":         EqualFilter("username"),
		"outbound":         EqualFilter("outbound"),
		"connection_type":  EqualFilter("connection_type"),
		"lock_type":        EqualFilter("lock_type"),
		"created_at_start": GreaterThanFilter("created_at"),
		"created_at_end":   LessThanFilter("created_at"),
		"updated_at_start": GreaterThanFilter("updated_at"),
		"updated_at_end":   LessThanFilter("updated_at"),
		"sort_asc":         SortAscFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "lock_type", "count", "created_at", "updated_at"}),
		"sort_desc":        SortDescFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "lock_type", "count", "created_at", "updated_at"}),
		"offset":           OffsetFilter(),
		"limit":            LimitFilter(),
	}
	bandwidthLimiterFilters = map[string]Filter{
		"id": EqualFilter("id"),
		"pk": EqualFilter("id"),
		"squad_id_in": ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.SQLite.NewSelectBuilder().
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
		"strategy":         EqualFilter("strategy"),
		"mode":             EqualFilter("mode"),
		"username":         EqualFilter("username"),
		"created_at_start": GreaterThanFilter("created_at"),
		"created_at_end":   LessThanFilter("created_at"),
		"updated_at_start": GreaterThanFilter("updated_at"),
		"updated_at_end":   LessThanFilter("updated_at"),
		"sort_asc": ReplacedSortAscFilter(
			map[string]string{"speed": "raw_speed"},
			[]string{"id", "username", "outbound", "strategy", "connection_type", "mode", "raw_speed", "created_at", "updated_at"},
		),
		"sort_desc": ReplacedSortDescFilter(
			map[string]string{"speed": "raw_speed"},
			[]string{"id", "username", "outbound", "strategy", "connection_type", "mode", "raw_speed", "created_at", "updated_at"},
		),
		"offset": OffsetFilter(),
		"limit":  LimitFilter(),
	}
	trafficLimiterFilters = map[string]Filter{
		"id": EqualFilter("id"),
		"pk": EqualFilter("id"),
		"squad_id_in": ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.SQLite.NewSelectBuilder().
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
		"username":         EqualFilter("username"),
		"outbound":         EqualFilter("outbound"),
		"strategy":         EqualFilter("strategy"),
		"mode":             EqualFilter("mode"),
		"used_start":       SpeedGreaterEqualThanFilter("raw_used"),
		"used_end":         SpeedLessEqualThanFilter("raw_used"),
		"quota_start":      SpeedGreaterEqualThanFilter("raw_quota"),
		"quota_end":        SpeedLessEqualThanFilter("raw_quota"),
		"created_at_start": GreaterThanFilter("created_at"),
		"created_at_end":   LessThanFilter("created_at"),
		"updated_at_start": GreaterThanFilter("updated_at"),
		"updated_at_end":   LessThanFilter("updated_at"),
		"sort_asc": ReplacedSortAscFilter(
			map[string]string{"used": "raw_used", "quota": "raw_quota"},
			[]string{"id", "username", "outbound", "strategy", "mode", "raw_used", "raw_quota", "created_at", "updated_at"},
		),
		"sort_desc": ReplacedSortDescFilter(
			map[string]string{"used": "raw_used", "quota": "raw_quota"},
			[]string{"id", "username", "outbound", "strategy", "mode", "raw_used", "raw_quota", "created_at", "updated_at"},
		),
		"offset": OffsetFilter(),
		"limit":  LimitFilter(),
	}
	rateLimiterFilters = map[string]Filter{
		"id": EqualFilter("id"),
		"pk": EqualFilter("id"),
		"squad_id_in": ExistsAndWhereInFilter(func() *sqlbuilder.SelectBuilder {
			return sqlbuilder.SQLite.NewSelectBuilder().
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
		"strategy":         EqualFilter("strategy"),
		"username":         EqualFilter("username"),
		"outbound":         EqualFilter("outbound"),
		"connection_type":  EqualFilter("connection_type"),
		"interval":         EqualFilter("interval"),
		"count_start":      GreaterEqualThanFilter("count"),
		"count_end":        LessEqualThanFilter("count"),
		"created_at_start": GreaterThanFilter("created_at"),
		"created_at_end":   LessThanFilter("created_at"),
		"updated_at_start": GreaterThanFilter("updated_at"),
		"updated_at_end":   LessThanFilter("updated_at"),
		"sort_asc":         SortAscFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "count", "interval", "created_at", "updated_at"}),
		"sort_desc":        SortDescFilter([]string{"id", "username", "outbound", "strategy", "connection_type", "count", "interval", "created_at", "updated_at"}),
		"offset":           OffsetFilter(),
		"limit":            LimitFilter(),
	}
}
