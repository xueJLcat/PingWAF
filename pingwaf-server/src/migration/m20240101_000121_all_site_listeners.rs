use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(r#"CREATE OR REPLACE VIEW panel_site_listeners AS
                SELECT a.id AS agent_id, s.id AS site_id, s.status,
                       split_part(listener, ':', 2)::integer AS port
                FROM agents a JOIN api_keys k ON k.id = a.api_key_id
                JOIN sites s ON s.user_id = k.user_id AND (
                    (a.site_scope='all' AND (a.site_id IS NULL OR a.site_id=s.id)
                     AND (s.ingress_port IS NULL OR EXISTS (SELECT FROM managed_config_generations g
                         WHERE g.agent_id=a.id AND g.session_id IS NOT NULL)))
                    OR (a.site_scope='selected' AND EXISTS (SELECT FROM agent_sites n WHERE n.agent_id=a.id AND n.site_id=s.id))
                )
                CROSS JOIN LATERAL unnest(CASE WHEN s.ingress_port IS NULL THEN ARRAY['http:80','https:443']
                    ELSE array_prepend(s.ingress_protocol || ':' || s.ingress_port::text,s.additional_ingresses) END) listener;
            DO $$ DECLARE node uuid; BEGIN
                FOR node IN SELECT id FROM agents WHERE site_scope='all' ORDER BY id LOOP
                    PERFORM validate_panel_node(node);
                END LOOP;
            END $$;
        "#).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(r#"CREATE OR REPLACE VIEW panel_site_listeners AS
                SELECT a.id AS agent_id, s.id AS site_id, s.status,
                       split_part(listener, ':', 2)::integer AS port
                FROM agents a JOIN api_keys k ON k.id = a.api_key_id
                JOIN sites s ON s.user_id = k.user_id AND (
                    (a.site_scope='all' AND s.ingress_port IS NULL AND (a.site_id IS NULL OR a.site_id=s.id))
                    OR (a.site_scope='selected' AND EXISTS (SELECT FROM agent_sites n WHERE n.agent_id=a.id AND n.site_id=s.id))
                )
                CROSS JOIN LATERAL unnest(CASE WHEN s.ingress_port IS NULL THEN ARRAY['http:80','https:443']
                    ELSE array_prepend(s.ingress_protocol || ':' || s.ingress_port::text,s.additional_ingresses) END) listener;
        "#).await?;
        Ok(())
    }
}
