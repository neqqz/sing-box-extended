package postgresql

import (
	"database/sql"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/sagernet/sing-box/common/migrate/source"
)

var migrations = map[string]string{
	"1_initialize_schema.up.sql": `
        CREATE TABLE squads (
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            created_at  TIMESTAMP NOT NULL,
            updated_at  TIMESTAMP NOT NULL
        );

        CREATE TABLE nodes (
            uuid        VARCHAR(36) PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            created_at  TIMESTAMP NOT NULL,
            updated_at  TIMESTAMP NOT NULL
        );

        CREATE TABLE node_to_squad (
            node_uuid VARCHAR(36) NOT NULL,
            squad_id INTEGER NOT NULL,
            PRIMARY KEY (node_uuid, squad_id),
            FOREIGN KEY (node_uuid) REFERENCES nodes(uuid) ON DELETE CASCADE,
            FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT
        );

        CREATE TABLE users (
            id          SERIAL PRIMARY KEY,
            node_uuid   VARCHAR(36),
            username    TEXT NOT NULL,
            inbound     TEXT NOT NULL,
            type        TEXT NOT NULL,
            uuid        TEXT NOT NULL,
            password    TEXT NOT NULL,
            secret      TEXT NOT NULL,
            flow        TEXT NOT NULL,
            alter_id    INTEGER NOT NULL,
            created_at  TIMESTAMP NOT NULL,
            updated_at  TIMESTAMP NOT NULL,
            UNIQUE (username, inbound)
        );

        CREATE TABLE user_to_squad (
            user_id  INTEGER NOT NULL,
            squad_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, squad_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT
        );

        CREATE TABLE connection_limiters (
            id              SERIAL PRIMARY KEY,
            username        TEXT NOT NULL,
            outbound        TEXT NOT NULL,
            strategy        TEXT NOT NULL,
            connection_type TEXT NOT NULL,
            lock_type       TEXT NOT NULL,
            count           INTEGER NOT NULL,
            created_at      TIMESTAMP NOT NULL,
            updated_at      TIMESTAMP NOT NULL,
            UNIQUE (username, outbound)
        );

        CREATE TABLE connection_limiter_to_squad (
            connection_limiter_id  INTEGER NOT NULL,
            squad_id INTEGER NOT NULL,
            PRIMARY KEY (connection_limiter_id, squad_id),
            FOREIGN KEY (connection_limiter_id) REFERENCES connection_limiters(id) ON DELETE CASCADE,
            FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT
        );

        CREATE TABLE bandwidth_limiters (
            id              SERIAL PRIMARY KEY,
            username        TEXT NOT NULL,
            outbound        TEXT NOT NULL,
            strategy        TEXT NOT NULL,
            mode            TEXT NOT NULL,
            connection_type TEXT NOT NULL,
            speed           TEXT NOT NULL,
            raw_speed       BIGINT NOT NULL DEFAULT 0,
            created_at      TIMESTAMP NOT NULL,
            updated_at      TIMESTAMP NOT NULL,
            UNIQUE (username, outbound)
        );

        CREATE TABLE bandwidth_limiter_to_squad (
            bandwidth_limiter_id  INTEGER NOT NULL,
            squad_id INTEGER NOT NULL,
            PRIMARY KEY (bandwidth_limiter_id, squad_id),
            FOREIGN KEY (bandwidth_limiter_id) REFERENCES bandwidth_limiters(id) ON DELETE CASCADE,
            FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT
        );
    `,
	"1_initialize_schema.down.sql": `
        DROP TABLE IF EXISTS bandwidth_limiter_to_squad;
        DROP TABLE IF EXISTS bandwidth_limiters;
        DROP TABLE IF EXISTS connection_limiter_to_squad;
        DROP TABLE IF EXISTS connection_limiters;
        DROP TABLE IF EXISTS user_to_squad;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS node_to_squad;
        DROP TABLE IF EXISTS nodes;
        DROP TABLE IF EXISTS squads;
    `,
	"2_init_limiters_and_indexes.up.sql": `
        CREATE TABLE traffic_limiters (
            id              SERIAL PRIMARY KEY,
            username        TEXT NOT NULL,
            outbound        TEXT NOT NULL,
            strategy        TEXT NOT NULL,
            mode            TEXT NOT NULL,
            raw_used        BIGINT NOT NULL DEFAULT 0,
            quota           TEXT NOT NULL,
            raw_quota       BIGINT NOT NULL DEFAULT 0,
            created_at      TIMESTAMP NOT NULL,
            updated_at      TIMESTAMP NOT NULL,
            UNIQUE (username, outbound)
        );

        CREATE TABLE traffic_limiter_to_squad (
            traffic_limiter_id  INTEGER NOT NULL,
            squad_id INTEGER NOT NULL,
            PRIMARY KEY (traffic_limiter_id, squad_id),
            FOREIGN KEY (traffic_limiter_id) REFERENCES traffic_limiters(id) ON DELETE CASCADE,
            FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE CASCADE
        );

        CREATE TABLE rate_limiters (
            id              SERIAL PRIMARY KEY,
            username        TEXT NOT NULL,
            outbound        TEXT NOT NULL,
            strategy        TEXT NOT NULL,
            connection_type TEXT NOT NULL,
            count           INTEGER NOT NULL,
            interval        TEXT NOT NULL,
            created_at      TIMESTAMP NOT NULL,
            updated_at      TIMESTAMP NOT NULL,
            UNIQUE (username, outbound)
        );

        CREATE TABLE rate_limiter_to_squad (
            rate_limiter_id  INTEGER NOT NULL,
            squad_id INTEGER NOT NULL,
            PRIMARY KEY (rate_limiter_id, squad_id),
            FOREIGN KEY (rate_limiter_id) REFERENCES rate_limiters(id) ON DELETE CASCADE,
            FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE CASCADE
        );

        ALTER TABLE bandwidth_limiters ADD COLUMN flow_keys JSONB NOT NULL DEFAULT '[]'::jsonb;

        UPDATE connection_limiters SET lock_type = 'default' WHERE lock_type = '';

        ALTER TABLE node_to_squad
            DROP CONSTRAINT node_to_squad_squad_id_fkey,
            ADD CONSTRAINT node_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE CASCADE;

        ALTER TABLE user_to_squad
            DROP CONSTRAINT user_to_squad_squad_id_fkey,
            ADD CONSTRAINT user_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE CASCADE;

        ALTER TABLE connection_limiter_to_squad
            DROP CONSTRAINT connection_limiter_to_squad_squad_id_fkey,
            ADD CONSTRAINT connection_limiter_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE CASCADE;

        ALTER TABLE bandwidth_limiter_to_squad
            DROP CONSTRAINT bandwidth_limiter_to_squad_squad_id_fkey,
            ADD CONSTRAINT bandwidth_limiter_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE CASCADE;

        CREATE INDEX idx_squads_created_at ON squads(created_at);
        CREATE INDEX idx_squads_updated_at ON squads(updated_at);

        CREATE INDEX idx_nodes_created_at ON nodes(created_at);
        CREATE INDEX idx_nodes_updated_at ON nodes(updated_at);

        CREATE INDEX idx_node_to_squad_squad_id ON node_to_squad(squad_id);

        CREATE INDEX idx_users_node_uuid   ON users(node_uuid);
        CREATE INDEX idx_users_inbound     ON users(inbound);
        CREATE INDEX idx_users_type        ON users(type);
        CREATE INDEX idx_users_created_at  ON users(created_at);
        CREATE INDEX idx_users_updated_at  ON users(updated_at);

        CREATE INDEX idx_user_to_squad_squad_id ON user_to_squad(squad_id);

        CREATE INDEX idx_connection_limiters_outbound        ON connection_limiters(outbound);
        CREATE INDEX idx_connection_limiters_strategy        ON connection_limiters(strategy);
        CREATE INDEX idx_connection_limiters_connection_type ON connection_limiters(connection_type);
        CREATE INDEX idx_connection_limiters_lock_type       ON connection_limiters(lock_type);
        CREATE INDEX idx_connection_limiters_created_at      ON connection_limiters(created_at);
        CREATE INDEX idx_connection_limiters_updated_at      ON connection_limiters(updated_at);

        CREATE INDEX idx_connection_limiter_to_squad_squad_id ON connection_limiter_to_squad(squad_id);

        CREATE INDEX idx_bandwidth_limiters_outbound        ON bandwidth_limiters(outbound);
        CREATE INDEX idx_bandwidth_limiters_strategy        ON bandwidth_limiters(strategy);
        CREATE INDEX idx_bandwidth_limiters_mode            ON bandwidth_limiters(mode);
        CREATE INDEX idx_bandwidth_limiters_connection_type ON bandwidth_limiters(connection_type);
        CREATE INDEX idx_bandwidth_limiters_raw_speed       ON bandwidth_limiters(raw_speed);
        CREATE INDEX idx_bandwidth_limiters_created_at      ON bandwidth_limiters(created_at);
        CREATE INDEX idx_bandwidth_limiters_updated_at      ON bandwidth_limiters(updated_at);

        CREATE INDEX idx_bandwidth_limiter_to_squad_squad_id ON bandwidth_limiter_to_squad(squad_id);

        CREATE INDEX idx_traffic_limiters_outbound    ON traffic_limiters(outbound);
        CREATE INDEX idx_traffic_limiters_strategy    ON traffic_limiters(strategy);
        CREATE INDEX idx_traffic_limiters_mode        ON traffic_limiters(mode);
        CREATE INDEX idx_traffic_limiters_raw_used    ON traffic_limiters(raw_used);
        CREATE INDEX idx_traffic_limiters_raw_quota   ON traffic_limiters(raw_quota);
        CREATE INDEX idx_traffic_limiters_created_at  ON traffic_limiters(created_at);
        CREATE INDEX idx_traffic_limiters_updated_at  ON traffic_limiters(updated_at);

        CREATE INDEX idx_traffic_limiter_to_squad_squad_id ON traffic_limiter_to_squad(squad_id);

        CREATE INDEX idx_rate_limiters_outbound        ON rate_limiters(outbound);
        CREATE INDEX idx_rate_limiters_strategy        ON rate_limiters(strategy);
        CREATE INDEX idx_rate_limiters_connection_type ON rate_limiters(connection_type);
        CREATE INDEX idx_rate_limiters_interval        ON rate_limiters("interval");
        CREATE INDEX idx_rate_limiters_count           ON rate_limiters(count);
        CREATE INDEX idx_rate_limiters_created_at      ON rate_limiters(created_at);
        CREATE INDEX idx_rate_limiters_updated_at      ON rate_limiters(updated_at);

        CREATE INDEX idx_rate_limiter_to_squad_squad_id ON rate_limiter_to_squad(squad_id);

        UPDATE connection_limiters SET connection_type = 'source_ip' WHERE connection_type = 'ip';
        UPDATE bandwidth_limiters  SET connection_type = 'source_ip' WHERE connection_type = 'ip';
        UPDATE rate_limiters       SET connection_type = 'source_ip' WHERE connection_type = 'ip';
        UPDATE bandwidth_limiters
            SET flow_keys = REPLACE(flow_keys::text, '"ip"', '"source_ip"')::jsonb
            WHERE flow_keys @> '["ip"]'::jsonb;

        UPDATE bandwidth_limiters SET mode = 'bidirectional' WHERE mode = 'duplex';
        UPDATE traffic_limiters   SET mode = 'bidirectional' WHERE mode = 'duplex';
    `,
	"2_init_limiters_and_indexes.down.sql": `
        UPDATE traffic_limiters   SET mode = 'duplex' WHERE mode = 'bidirectional';
        UPDATE bandwidth_limiters SET mode = 'duplex' WHERE mode = 'bidirectional';

        UPDATE bandwidth_limiters
            SET flow_keys = REPLACE(flow_keys::text, '"source_ip"', '"ip"')::jsonb
            WHERE flow_keys @> '["source_ip"]'::jsonb;
        UPDATE rate_limiters       SET connection_type = 'ip' WHERE connection_type = 'source_ip';
        UPDATE bandwidth_limiters  SET connection_type = 'ip' WHERE connection_type = 'source_ip';
        UPDATE connection_limiters SET connection_type = 'ip' WHERE connection_type = 'source_ip';

        DROP INDEX IF EXISTS idx_rate_limiter_to_squad_squad_id;
        DROP INDEX IF EXISTS idx_rate_limiters_updated_at;
        DROP INDEX IF EXISTS idx_rate_limiters_created_at;
        DROP INDEX IF EXISTS idx_rate_limiters_count;
        DROP INDEX IF EXISTS idx_rate_limiters_interval;
        DROP INDEX IF EXISTS idx_rate_limiters_connection_type;
        DROP INDEX IF EXISTS idx_rate_limiters_strategy;
        DROP INDEX IF EXISTS idx_rate_limiters_outbound;

        DROP INDEX IF EXISTS idx_traffic_limiter_to_squad_squad_id;
        DROP INDEX IF EXISTS idx_traffic_limiters_updated_at;
        DROP INDEX IF EXISTS idx_traffic_limiters_created_at;
        DROP INDEX IF EXISTS idx_traffic_limiters_raw_quota;
        DROP INDEX IF EXISTS idx_traffic_limiters_raw_used;
        DROP INDEX IF EXISTS idx_traffic_limiters_mode;
        DROP INDEX IF EXISTS idx_traffic_limiters_strategy;
        DROP INDEX IF EXISTS idx_traffic_limiters_outbound;

        DROP INDEX IF EXISTS idx_bandwidth_limiter_to_squad_squad_id;
        DROP INDEX IF EXISTS idx_bandwidth_limiters_updated_at;
        DROP INDEX IF EXISTS idx_bandwidth_limiters_created_at;
        DROP INDEX IF EXISTS idx_bandwidth_limiters_raw_speed;
        DROP INDEX IF EXISTS idx_bandwidth_limiters_connection_type;
        DROP INDEX IF EXISTS idx_bandwidth_limiters_mode;
        DROP INDEX IF EXISTS idx_bandwidth_limiters_strategy;
        DROP INDEX IF EXISTS idx_bandwidth_limiters_outbound;

        DROP INDEX IF EXISTS idx_connection_limiter_to_squad_squad_id;
        DROP INDEX IF EXISTS idx_connection_limiters_updated_at;
        DROP INDEX IF EXISTS idx_connection_limiters_created_at;
        DROP INDEX IF EXISTS idx_connection_limiters_lock_type;
        DROP INDEX IF EXISTS idx_connection_limiters_connection_type;
        DROP INDEX IF EXISTS idx_connection_limiters_strategy;
        DROP INDEX IF EXISTS idx_connection_limiters_outbound;

        DROP INDEX IF EXISTS idx_user_to_squad_squad_id;
        DROP INDEX IF EXISTS idx_users_updated_at;
        DROP INDEX IF EXISTS idx_users_created_at;
        DROP INDEX IF EXISTS idx_users_type;
        DROP INDEX IF EXISTS idx_users_inbound;
        DROP INDEX IF EXISTS idx_users_node_uuid;

        DROP INDEX IF EXISTS idx_node_to_squad_squad_id;

        DROP INDEX IF EXISTS idx_nodes_updated_at;
        DROP INDEX IF EXISTS idx_nodes_created_at;

        DROP INDEX IF EXISTS idx_squads_updated_at;
        DROP INDEX IF EXISTS idx_squads_created_at;

        ALTER TABLE bandwidth_limiter_to_squad
            DROP CONSTRAINT bandwidth_limiter_to_squad_squad_id_fkey,
            ADD CONSTRAINT bandwidth_limiter_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT;

        ALTER TABLE connection_limiter_to_squad
            DROP CONSTRAINT connection_limiter_to_squad_squad_id_fkey,
            ADD CONSTRAINT connection_limiter_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT;

        ALTER TABLE user_to_squad
            DROP CONSTRAINT user_to_squad_squad_id_fkey,
            ADD CONSTRAINT user_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT;

        ALTER TABLE node_to_squad
            DROP CONSTRAINT node_to_squad_squad_id_fkey,
            ADD CONSTRAINT node_to_squad_squad_id_fkey
                FOREIGN KEY (squad_id) REFERENCES squads(id) ON DELETE RESTRICT;

        UPDATE connection_limiters SET lock_type = '' WHERE lock_type = 'default';
        ALTER TABLE bandwidth_limiters DROP COLUMN flow_keys;
        DROP TABLE IF EXISTS rate_limiter_to_squad;
        DROP TABLE IF EXISTS rate_limiters;
        DROP TABLE IF EXISTS traffic_limiter_to_squad;
        DROP TABLE IF EXISTS traffic_limiters;
    `,
	"3_add_authorized_keys.up.sql": `
        ALTER TABLE users ADD COLUMN authorized_keys JSONB NOT NULL DEFAULT '[]'::jsonb;
    `,
	"3_add_authorized_keys.down.sql": `
        ALTER TABLE users DROP COLUMN authorized_keys;
    `,
}

func Migrate(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}
	sourceDriver := source.NewRawDriver(migrations)
	if err := sourceDriver.Init(); err != nil {
		return err
	}
	m, err := migrate.NewWithInstance(
		"raw",
		sourceDriver,
		"postgres",
		driver,
	)
	if err != nil {
		return err
	}
	return m.Up()
}
