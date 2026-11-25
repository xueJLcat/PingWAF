use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(r#"
            CREATE TABLE node_listener_policies (
                id uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
                addresses text[] CHECK (cardinality(addresses) BETWEEN 1 AND 32),
                revision bigint NOT NULL DEFAULT 0,
                updated_by text NOT NULL DEFAULT ''
            );
            INSERT INTO node_listener_policies(id) SELECT id FROM agents;
            CREATE FUNCTION initialize_node_listener_policy() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                INSERT INTO node_listener_policies(id, addresses) VALUES (NEW.id, ARRAY['0.0.0.0']);
                RETURN NEW;
            END $$;
            CREATE TRIGGER initialize_node_listeners AFTER INSERT ON agents
                FOR EACH ROW EXECUTE FUNCTION initialize_node_listener_policy();
            CREATE TABLE node_listener_overrides (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
                addresses text[] NOT NULL CHECK(cardinality(addresses) BETWEEN 1 AND 32),
                UNIQUE(agent_id, site_id, port)
            );
            CREATE VIEW panel_site_listeners AS
                SELECT a.id AS agent_id, s.id AS site_id, s.status,
                       split_part(listener, ':', 2)::integer AS port
                FROM agents a JOIN api_keys k ON k.id = a.api_key_id
                JOIN sites s ON s.user_id = k.user_id AND (
                    (a.site_scope='all' AND s.ingress_port IS NULL AND (a.site_id IS NULL OR a.site_id=s.id))
                    OR (a.site_scope='selected' AND EXISTS (SELECT FROM agent_sites n WHERE n.agent_id=a.id AND n.site_id=s.id))
                )
                CROSS JOIN LATERAL unnest(CASE WHEN s.ingress_port IS NULL THEN ARRAY['http:80','https:443']
                    ELSE array_prepend(s.ingress_protocol || ':' || s.ingress_port::text,s.additional_ingresses) END) listener;
            CREATE FUNCTION validate_panel_node(node uuid) RETURNS void LANGUAGE plpgsql AS $$
            DECLARE base text[];
            BEGIN
                SELECT addresses INTO base FROM node_listener_policies WHERE id=node FOR UPDATE;
                IF NOT FOUND OR base IS NULL THEN RETURN; END IF;
                IF EXISTS (SELECT FROM node_listener_overrides o WHERE o.agent_id=node AND NOT EXISTS (
                    SELECT FROM panel_site_listeners l WHERE l.agent_id=node AND l.site_id=o.site_id AND l.port=o.port
                )) THEN RAISE check_violation USING CONSTRAINT='panel_override_scope', MESSAGE='address override requires a site and port assigned to this node'; END IF;
                IF EXISTS (SELECT l.port FROM panel_site_listeners l LEFT JOIN node_listener_overrides o
                    USING(agent_id,site_id,port) WHERE l.agent_id=node GROUP BY l.port
                    HAVING count(DISTINCT coalesce(o.addresses,base))>1)
                THEN RAISE check_violation USING CONSTRAINT='panel_shared_addresses', MESSAGE='sites sharing a port require identical bind addresses'; END IF;
                IF (SELECT count(DISTINCT (l.port,addr)) FROM panel_site_listeners l LEFT JOIN node_listener_overrides o
                    USING(agent_id,site_id,port) CROSS JOIN LATERAL unnest(coalesce(o.addresses,base)) addr
                    WHERE l.agent_id=node AND l.status='active')>32
                THEN RAISE check_violation USING CONSTRAINT='panel_socket_limit', MESSAGE='node listener limit of 32 sockets exceeded'; END IF;
            END $$;
            CREATE FUNCTION check_panel_listeners() RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE node uuid; affected_site uuid;
            BEGIN
                IF TG_TABLE_NAME='sites' THEN
                    affected_site := coalesce(NEW.id,OLD.id);
                    DELETE FROM node_listener_overrides o WHERE o.site_id=affected_site AND NOT EXISTS (
                        SELECT FROM panel_site_listeners l WHERE (l.agent_id,l.site_id,l.port)=(o.agent_id,o.site_id,o.port));
                    FOR node IN SELECT DISTINCT agent_id FROM panel_site_listeners WHERE site_id=affected_site ORDER BY agent_id LOOP
                        PERFORM validate_panel_node(node);
                    END LOOP;
                ELSE
                    IF TG_TABLE_NAME IN ('agents','node_listener_policies') THEN node:=coalesce(NEW.id,OLD.id);
                    ELSE node:=coalesce(NEW.agent_id,OLD.agent_id); END IF;
                    IF TG_TABLE_NAME IN ('agents','agent_sites') THEN
                        DELETE FROM node_listener_overrides o WHERE o.agent_id=node AND NOT EXISTS (
                            SELECT FROM panel_site_listeners l WHERE (l.agent_id,l.site_id,l.port)=(o.agent_id,o.site_id,o.port));
                    END IF;
                    PERFORM validate_panel_node(node);
                END IF;
                RETURN NULL;
            END $$;
            CREATE CONSTRAINT TRIGGER check_site_panel_listeners AFTER INSERT OR UPDATE OF ingress_port,ingress_protocol,additional_ingresses,status,user_id
                ON sites DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_panel_listeners();
            CREATE CONSTRAINT TRIGGER check_agent_panel_listeners AFTER UPDATE OF site_id,site_scope,api_key_id
                ON agents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_panel_listeners();
            CREATE CONSTRAINT TRIGGER check_assignment_panel_listeners AFTER INSERT OR UPDATE OR DELETE
                ON agent_sites DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_panel_listeners();
            CREATE CONSTRAINT TRIGGER check_policy_panel_listeners AFTER INSERT OR UPDATE
                ON node_listener_policies DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_panel_listeners();
            CREATE CONSTRAINT TRIGGER check_override_panel_listeners AFTER INSERT OR UPDATE OR DELETE
                ON node_listener_overrides DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_panel_listeners();
        "#).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
            DROP TRIGGER check_site_panel_listeners ON sites;
            DROP TRIGGER check_agent_panel_listeners ON agents;
            DROP TRIGGER check_assignment_panel_listeners ON agent_sites;
            DROP FUNCTION check_panel_listeners() CASCADE;
            DROP FUNCTION validate_panel_node(uuid);
            DROP VIEW panel_site_listeners;
            DROP TRIGGER initialize_node_listeners ON agents;
            DROP FUNCTION initialize_node_listener_policy();
            DROP TABLE node_listener_overrides, node_listener_policies;
        ",
            )
            .await?;
        Ok(())
    }
}
